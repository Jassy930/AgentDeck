//! Relay v2 真实 listener synthetic E2E；身份、TLS bundle 与 payload 均不持久化。

use std::fs::OpenOptions;
use std::io::Read;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use agentdeck_crypto::{
    AeadReceivingKey, AeadSendingKey, SecretAeadKey, SenderCounter, SigningKey,
    ValidatedRelayReceiptVerifyKey, open_symmetric, seal_symmetric, sha256,
    sign_authentication_transcript, sign_sealed, sign_tbs, verify_sealed,
};
use agentdeck_protocol::e2ee::{
    E2EE_FORMAT_VERSION, KeyId, KeyPurpose, OuterContextV1, OuterFrameKind, SealedPayloadKind,
};
use agentdeck_protocol::relay_v2::auth::{
    AuthenticationRole, AuthenticationTranscriptV1, CertRole,
};
use agentdeck_protocol::relay_v2::frame::{
    AcceptedRef, AuthProof, Authenticate, GrantCommitted, InstallGrant, Publish, RegisterStream,
    ReplayComplete, Reply, RevocationCommitted, RevokeDevice, RouteAccepted, SealedBlob, Send,
    Subscribe,
};
use agentdeck_protocol::relay_v2::{
    DeviceRevocation, DeviceRouteId, ENROLLMENT_BUNDLE_VERSION, Ed25519Signature,
    EnrollmentBundleV2, GrantSerial, LinkGeneration, MachineEnrollmentRequestV1, MachineRouteId,
    OpaqueRouteFrame, PublicKeyBytes, RELAY_PROTOCOL_VERSION, RelayFrameBody, RelayGrant,
    RelayServerId, RequestRouteId, RootKeyId, SignedCertificate, StreamCursor, StreamGenerationId,
    StreamRouteId, TrustEpoch, encode,
};
use agentdeck_relay_client::{
    EnrollmentClientConfig, LinkAuthenticator, RelayClient, RelayClientConfig, RelayClientError,
    RelayEnrollmentClient, RelayTlsPolicy,
};
use async_trait::async_trait;
use rand::RngCore as _;
use serde::Serialize;
use zeroize::Zeroizing;

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

const BUNDLE_MAX_BYTES: u64 = 64 * 1024;
const STEP_TIMEOUT: Duration = Duration::from_secs(5);
const SYNTHETIC_SENTINEL: &[u8] = b"AGENTDECK_SYNTHETIC_E2EE_SENTINEL_9F4A7C21";

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyntheticReport {
    ok: bool,
    relay_protocol_version: u16,
    transport: &'static str,
    checks: [&'static str; 5],
}

#[derive(Debug)]
pub struct SyntheticError(&'static str);

impl SyntheticError {
    pub fn code(&self) -> &'static str {
        self.0
    }
}

struct MachineAuthenticator {
    machine_route: MachineRouteId,
    link: SigningKey,
    link_cert: SignedCertificate,
}

#[async_trait]
impl LinkAuthenticator for MachineAuthenticator {
    fn proof(&self) -> AuthProof {
        AuthProof::MachineLink {
            machine_route: self.machine_route,
            link_cert: self.link_cert.clone(),
        }
    }

    async fn authenticate(
        &self,
        challenge: &agentdeck_protocol::relay_v2::frame::Challenge,
    ) -> Result<Authenticate, RelayClientError> {
        let transcript = AuthenticationTranscriptV1 {
            role: AuthenticationRole::MachineLink,
            challenge_nonce: challenge.challenge_nonce,
            connection_instance: challenge.connection_instance,
            relay_server_id: challenge.relay_server_id,
            relay_protocol_version: RELAY_PROTOCOL_VERSION,
            machine_route: self.machine_route,
            device_route: None,
            serial_or_generation: self.link_cert.generation.value(),
            credential_sha256: self.link_cert.canonical_sha256(),
        };
        Ok(Authenticate {
            proof: self.proof(),
            signature: sign_authentication_transcript(&self.link, &transcript).into(),
        })
    }
}

struct DeviceAuthenticator {
    device: SigningKey,
    grant: RelayGrant,
}

#[async_trait]
impl LinkAuthenticator for DeviceAuthenticator {
    fn proof(&self) -> AuthProof {
        AuthProof::Device {
            relay_grant: self.grant.clone(),
        }
    }

    async fn authenticate(
        &self,
        challenge: &agentdeck_protocol::relay_v2::frame::Challenge,
    ) -> Result<Authenticate, RelayClientError> {
        let transcript = AuthenticationTranscriptV1 {
            role: AuthenticationRole::Device,
            challenge_nonce: challenge.challenge_nonce,
            connection_instance: challenge.connection_instance,
            relay_server_id: challenge.relay_server_id,
            relay_protocol_version: RELAY_PROTOCOL_VERSION,
            machine_route: self.grant.machine_route,
            device_route: Some(self.grant.device_route),
            serial_or_generation: self.grant.grant_serial.value(),
            credential_sha256: self.grant.canonical_sha256(),
        };
        Ok(Authenticate {
            proof: self.proof(),
            signature: sign_authentication_transcript(&self.device, &transcript).into(),
        })
    }
}

pub async fn run(bundle_path: &Path) -> Result<SyntheticReport, SyntheticError> {
    let bundle = load_bundle(bundle_path)?;
    let pins = decode_pins(&bundle.spki_pins)?;
    let tls = RelayTlsPolicy::pinned_spki(pins)
        .map_err(|_| SyntheticError("remote.synthetic.bundle_invalid"))?;
    let client_config = RelayClientConfig::new(&bundle.public_wss_url, bundle.relay_server_id, tls)
        .map_err(|_| SyntheticError("remote.synthetic.bundle_invalid"))?;
    if client_config.origin() != bundle.public_wss_url {
        return Err(SyntheticError("remote.synthetic.bundle_invalid"));
    }

    let machine_route = MachineRouteId::random();
    let root_key_id = RootKeyId::random();
    let trust_epoch = TrustEpoch::new(1);
    let root = random_signing_key()?;
    let link = random_signing_key()?;
    let data = random_signing_key()?;
    let link_cert = signed_certificate(
        &root,
        &link,
        bundle.relay_server_id,
        machine_route,
        root_key_id,
        trust_epoch,
        CertRole::Link,
        bundle.expires_at_ms.saturating_add(60 * 60 * 1_000),
    );
    let data_cert = signed_certificate(
        &root,
        &data,
        bundle.relay_server_id,
        machine_route,
        root_key_id,
        trust_epoch,
        CertRole::Data,
        bundle.expires_at_ms.saturating_add(60 * 60 * 1_000),
    );
    let request = MachineEnrollmentRequestV1 {
        code: bundle.code.clone(),
        machine_route,
        root_pubkey: PublicKeyBytes(root.verifying_key().to_bytes()),
        link_cert: link_cert.clone(),
        data_cert,
    };
    RelayEnrollmentClient::enroll_machine(
        EnrollmentClientConfig::new(client_config.clone()),
        request,
    )
    .await
    .map_err(|_| SyntheticError("remote.synthetic.enrollment_failed"))?;

    let machine_auth: Arc<dyn LinkAuthenticator> = Arc::new(MachineAuthenticator {
        machine_route,
        link,
        link_cert,
    });
    let mut machine = RelayClient::connect(client_config.clone(), machine_auth)
        .await
        .map_err(|_| SyntheticError("remote.synthetic.machine_auth_failed"))?;

    let device_route = DeviceRouteId::random();
    let device = random_signing_key()?;
    let grant = signed_grant(
        &root,
        &device,
        bundle.relay_server_id,
        machine_route,
        device_route,
        root_key_id,
        trust_epoch,
    );
    send(
        &machine,
        RelayFrameBody::InstallGrant(InstallGrant {
            grant: grant.clone(),
        }),
    )
    .await?;
    let committed = recv(&mut machine, "remote.synthetic.grant_timeout").await?;
    if committed.body
        != RelayFrameBody::GrantCommitted(GrantCommitted {
            device_route,
            grant_serial: grant.grant_serial,
            grant_hash: grant.canonical_sha256(),
        })
    {
        return Err(SyntheticError("remote.synthetic.grant_invalid"));
    }

    let device_auth: Arc<dyn LinkAuthenticator> = Arc::new(DeviceAuthenticator { device, grant });
    let mut remote = RelayClient::connect(client_config.clone(), Arc::clone(&device_auth))
        .await
        .map_err(|_| SyntheticError("remote.synthetic.device_auth_failed"))?;

    let stream_route = StreamRouteId::random();
    let generation = StreamGenerationId::random();
    send(
        &machine,
        RelayFrameBody::RegisterStream(RegisterStream {
            machine_route,
            stream_route,
            generation,
        }),
    )
    .await?;
    let (sealed_stream, opened_plaintext) = e2ee_stream_blob(
        &data,
        machine_route,
        stream_route,
        generation,
        SYNTHETIC_SENTINEL,
    )?;
    if opened_plaintext != SYNTHETIC_SENTINEL
        || contains_subslice(&sealed_stream, SYNTHETIC_SENTINEL)
    {
        return Err(SyntheticError("remote.synthetic.e2ee_invalid"));
    }
    send(
        &machine,
        RelayFrameBody::Publish(Publish {
            stream_route,
            generation,
            stream_seq: 0,
            sealed_blob: SealedBlob(sealed_stream.clone()),
        }),
    )
    .await?;
    let published = recv(&mut machine, "remote.synthetic.publish_timeout").await?;
    if published.body
        != RelayFrameBody::RouteAccepted(RouteAccepted {
            accepted: AcceptedRef::StreamFrame {
                stream_route,
                stream_seq: 0,
            },
        })
    {
        return Err(SyntheticError("remote.synthetic.publish_invalid"));
    }
    send(
        &remote,
        RelayFrameBody::Subscribe(Subscribe {
            stream_route,
            generation,
            cursor: StreamCursor::BeforeFirst,
        }),
    )
    .await?;
    let replay = recv(&mut remote, "remote.synthetic.replay_timeout").await?;
    if replay.body
        != RelayFrameBody::Publish(Publish {
            stream_route,
            generation,
            stream_seq: 0,
            sealed_blob: SealedBlob(sealed_stream),
        })
    {
        return Err(SyntheticError("remote.synthetic.replay_invalid"));
    }
    let replay_complete = recv(&mut remote, "remote.synthetic.replay_timeout").await?;
    if replay_complete.body
        != RelayFrameBody::ReplayComplete(ReplayComplete {
            stream_route,
            generation,
            current_cursor: StreamCursor::At(0),
        })
    {
        return Err(SyntheticError("remote.synthetic.replay_invalid"));
    }

    let request_route = RequestRouteId::random();
    let request_blob = random_bytes::<48>()?;
    send(
        &remote,
        RelayFrameBody::Send(Send {
            device_route,
            request_route,
            sealed_blob: SealedBlob(request_blob.clone()),
        }),
    )
    .await?;
    let uplink = recv(&mut machine, "remote.synthetic.send_timeout").await?;
    if uplink.body
        != RelayFrameBody::Send(Send {
            device_route,
            request_route,
            sealed_blob: SealedBlob(request_blob),
        })
    {
        return Err(SyntheticError("remote.synthetic.send_invalid"));
    }
    expect_request_accepted(&mut remote, request_route).await?;

    let reply_blob = random_bytes::<48>()?;
    send(
        &machine,
        RelayFrameBody::Reply(Reply {
            device_route,
            request_route,
            sealed_blob: SealedBlob(reply_blob.clone()),
        }),
    )
    .await?;
    let downlink = recv(&mut remote, "remote.synthetic.reply_timeout").await?;
    if downlink.body
        != RelayFrameBody::Reply(Reply {
            device_route,
            request_route,
            sealed_blob: SealedBlob(reply_blob),
        })
    {
        return Err(SyntheticError("remote.synthetic.reply_invalid"));
    }
    expect_request_accepted(&mut machine, request_route).await?;

    let revocation = signed_revocation(
        &root,
        bundle.relay_server_id,
        machine_route,
        device_route,
        root_key_id,
        trust_epoch,
    );
    let terminal = OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body: RelayFrameBody::RevocationCommitted(RevocationCommitted {
            device_route,
            grant_serial: GrantSerial::new(1),
            signed_revocation: revocation.clone(),
        }),
    };
    send(
        &machine,
        RelayFrameBody::RevokeDevice(RevokeDevice { revocation }),
    )
    .await?;
    if recv(&mut machine, "remote.synthetic.revoke_timeout").await? != terminal
        || recv(&mut remote, "remote.synthetic.revoke_timeout").await? != terminal
    {
        return Err(SyntheticError("remote.synthetic.revoke_invalid"));
    }
    let reconnect = match RelayClient::connect(client_config, device_auth).await {
        Err(error) => error,
        Ok(_) => return Err(SyntheticError("remote.synthetic.revoke_replay_invalid")),
    };
    let terminal_bytes = encode(&terminal);
    if reconnect.authentication_terminal_frame() != Some(&terminal)
        || reconnect.authentication_terminal_bytes() != Some(terminal_bytes.as_slice())
    {
        return Err(SyntheticError("remote.synthetic.revoke_replay_invalid"));
    }

    Ok(SyntheticReport {
        ok: true,
        relay_protocol_version: RELAY_PROTOCOL_VERSION,
        transport: "wss+spki",
        checks: [
            "challenge-auth",
            "register-publish-subscribe-replay",
            "send-reply",
            "signed-revoke-terminal",
            "opaque-relay-payload",
        ],
    })
}

fn load_bundle(path: &Path) -> Result<EnrollmentBundleV2, SyntheticError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let file = options
        .open(path)
        .map_err(|_| SyntheticError("remote.synthetic.bundle_unreadable"))?;
    let metadata = file
        .metadata()
        .map_err(|_| SyntheticError("remote.synthetic.bundle_unreadable"))?;
    if !metadata.is_file() || metadata.len() > BUNDLE_MAX_BYTES {
        return Err(SyntheticError("remote.synthetic.bundle_invalid"));
    }
    #[cfg(unix)]
    if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
        return Err(SyntheticError("remote.synthetic.bundle_permissions"));
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(metadata.len() as usize));
    file.take(BUNDLE_MAX_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| SyntheticError("remote.synthetic.bundle_unreadable"))?;
    if bytes.len() as u64 > BUNDLE_MAX_BYTES {
        return Err(SyntheticError("remote.synthetic.bundle_invalid"));
    }
    let bundle: EnrollmentBundleV2 = serde_json::from_slice(&bytes)
        .map_err(|_| SyntheticError("remote.synthetic.bundle_invalid"))?;
    if bundle.version != ENROLLMENT_BUNDLE_VERSION
        || bundle.expires_at_ms <= unix_now_ms()
        || bundle.relay_server_id.as_bytes() == &[0; 16]
        || bundle.code.0 == [0; 32]
    {
        return Err(SyntheticError("remote.synthetic.bundle_invalid"));
    }
    let receipt_verify_key = ValidatedRelayReceiptVerifyKey::new(bundle.receipt_verify_key.clone())
        .map_err(|_| SyntheticError("remote.synthetic.bundle_invalid"))?;
    if receipt_verify_key.wire_anchor().relay_server_id != bundle.relay_server_id {
        return Err(SyntheticError("remote.synthetic.bundle_invalid"));
    }
    Ok(bundle)
}

fn decode_pins(
    values: &[agentdeck_protocol::relay_v2::Digest32],
) -> Result<Vec<[u8; 32]>, SyntheticError> {
    if !(1..=2).contains(&values.len())
        || values.iter().any(|value| value.0 == [0; 32])
        || (values.len() == 2 && values[0] == values[1])
    {
        return Err(SyntheticError("remote.synthetic.bundle_invalid"));
    }
    Ok(values.iter().map(|value| value.0).collect())
}

fn random_bytes<const N: usize>() -> Result<Vec<u8>, SyntheticError> {
    let mut bytes = vec![0_u8; N];
    rand::rngs::OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| SyntheticError("remote.synthetic.random_unavailable"))?;
    Ok(bytes)
}

fn random_signing_key() -> Result<SigningKey, SyntheticError> {
    let mut seed = Zeroizing::new([0_u8; 32]);
    rand::rngs::OsRng
        .try_fill_bytes(seed.as_mut())
        .map_err(|_| SyntheticError("remote.synthetic.random_unavailable"))?;
    Ok(SigningKey::from_seed(&seed))
}

#[allow(clippy::too_many_arguments)]
fn signed_certificate(
    root: &SigningKey,
    subject: &SigningKey,
    relay_server_id: RelayServerId,
    machine_route: MachineRouteId,
    root_key_id: RootKeyId,
    trust_epoch: TrustEpoch,
    cert_role: CertRole,
    not_after_ms: u64,
) -> SignedCertificate {
    let mut certificate = SignedCertificate {
        subject_pubkey: PublicKeyBytes(subject.verifying_key().to_bytes()),
        cert_role,
        generation: LinkGeneration::new(1),
        root_key_id,
        trust_epoch,
        not_after_ms: Some(not_after_ms),
        signature: Ed25519Signature([0; 64]),
    };
    certificate.signature = sign_tbs(
        root,
        &certificate.to_be_signed_v1(
            relay_server_id,
            machine_route,
            sha256(&root.verifying_key().to_bytes()),
        ),
    )
    .into();
    certificate
}

#[allow(clippy::too_many_arguments)]
fn signed_grant(
    root: &SigningKey,
    device: &SigningKey,
    relay_server_id: RelayServerId,
    machine_route: MachineRouteId,
    device_route: DeviceRouteId,
    root_key_id: RootKeyId,
    trust_epoch: TrustEpoch,
) -> RelayGrant {
    let mut grant = RelayGrant {
        machine_route,
        device_route,
        device_sign_pubkey: PublicKeyBytes(device.verifying_key().to_bytes()),
        grant_serial: GrantSerial::new(1),
        root_key_id,
        trust_epoch,
        signature: Ed25519Signature([0; 64]),
    };
    grant.signature = sign_tbs(
        root,
        &grant.to_be_signed_v1(relay_server_id, sha256(&root.verifying_key().to_bytes())),
    )
    .into();
    grant
}

#[allow(clippy::too_many_arguments)]
fn signed_revocation(
    root: &SigningKey,
    relay_server_id: RelayServerId,
    machine_route: MachineRouteId,
    device_route: DeviceRouteId,
    root_key_id: RootKeyId,
    trust_epoch: TrustEpoch,
) -> DeviceRevocation {
    let mut revocation = DeviceRevocation {
        machine_route,
        device_route,
        grant_serial: GrantSerial::new(1),
        root_key_id,
        trust_epoch,
        signature: Ed25519Signature([0; 64]),
    };
    revocation.signature = sign_tbs(
        root,
        &revocation.to_be_signed_v1(relay_server_id, sha256(&root.verifying_key().to_bytes())),
    )
    .into();
    revocation
}

fn e2ee_stream_blob(
    data_signing: &SigningKey,
    machine_route: MachineRouteId,
    stream_route: StreamRouteId,
    generation: StreamGenerationId,
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), SyntheticError> {
    let mut key_bytes = Zeroizing::new([0_u8; 32]);
    rand::rngs::OsRng
        .try_fill_bytes(key_bytes.as_mut())
        .map_err(|_| SyntheticError("remote.synthetic.random_unavailable"))?;
    let key_id = KeyId {
        purpose: KeyPurpose::ConversationDek,
        epoch: 1,
    };
    let context = OuterContextV1 {
        frame_kind: OuterFrameKind::ConversationPublish,
        relay_protocol_version: RELAY_PROTOCOL_VERSION,
        e2ee_format_version: E2EE_FORMAT_VERSION,
        machine_route: Some(machine_route),
        device_route: None,
        stream_route: Some(stream_route),
        request_route: None,
        stream_generation: Some(generation),
        stream_cursor: None,
        stream_seq: Some(0),
        message_key_epoch: 1,
    };
    let sending = AeadSendingKey::new(
        key_id,
        1,
        1,
        [0x21, 0x43, 0x65, 0x87],
        SecretAeadKey::from_bytes(*key_bytes),
    );
    let sealed = seal_symmetric(
        &sending,
        &context,
        SealedPayloadKind::ConversationEvent,
        plaintext,
        SenderCounter(0),
    )
    .map_err(|_| SyntheticError("remote.synthetic.e2ee_invalid"))?;
    let signed = sign_sealed(sealed, data_signing, &context);
    let wire = signed.to_wire_bytes();
    let verified = verify_sealed(signed, &data_signing.verifying_key(), &context)
        .map_err(|_| SyntheticError("remote.synthetic.e2ee_invalid"))?;
    let receiving = AeadReceivingKey::new(key_id, 1, SecretAeadKey::from_bytes(*key_bytes));
    let opened = open_symmetric(&receiving, &context, verified)
        .map_err(|_| SyntheticError("remote.synthetic.e2ee_invalid"))?;
    Ok((wire, opened))
}

async fn send(client: &RelayClient, body: RelayFrameBody) -> Result<(), SyntheticError> {
    client
        .send(OpaqueRouteFrame {
            version: RELAY_PROTOCOL_VERSION,
            body,
        })
        .await
        .map_err(|_| SyntheticError("remote.synthetic.send_failed"))
}

async fn recv(
    client: &mut RelayClient,
    timeout_code: &'static str,
) -> Result<OpaqueRouteFrame, SyntheticError> {
    tokio::time::timeout(STEP_TIMEOUT, client.recv())
        .await
        .map_err(|_| SyntheticError(timeout_code))?
        .map_err(|_| SyntheticError("remote.synthetic.receive_failed"))?
        .ok_or(SyntheticError("remote.synthetic.connection_closed"))
}

async fn expect_request_accepted(
    client: &mut RelayClient,
    request_route: RequestRouteId,
) -> Result<(), SyntheticError> {
    let accepted = recv(client, "remote.synthetic.accept_timeout").await?;
    if accepted.body
        != RelayFrameBody::RouteAccepted(RouteAccepted {
            accepted: AcceptedRef::Request { request_route },
        })
    {
        return Err(SyntheticError("remote.synthetic.accept_invalid"));
    }
    Ok(())
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn unix_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
        .unwrap_or(u64::MAX)
}
