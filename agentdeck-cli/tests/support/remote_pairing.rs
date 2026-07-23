use std::convert::Infallible;
use std::path::Path;

use agentdeck_cli::remote::keychain::RemoteKeyStore;
use agentdeck_cli::remote::paired_machine::{PairedMachineIdentity, PairedPromotionCoordinator};
use agentdeck_cli::remote::pending::{PendingPairingCoordinator, PreparedPairRequest};
use agentdeck_crypto::rand_core::{TryCryptoRng, TryRng};
use agentdeck_crypto::{
    HpkePrivateKey, PairResponseSealAuthority, SecretAeadKey, SigningKey, VerifyingKey,
    seal_key_directory_entry, seal_pair_response, sha256, sign_device_authorization,
    sign_key_directory, sign_tbs,
};
use agentdeck_protocol::e2ee::{
    AuthorizationCapabilityV1, AuthorizationPermissionV1, AuthorizationRequestV1,
    DeviceAuthorizationV1, E2EE_FORMAT_VERSION, KeyDirectorySignatureContextV1, KeyDirectoryV1,
    KeyPurpose, KeyUpdateInfoV1, MachineDataSignerBindingV1, OuterContextV1, OuterFrameKind,
    PairInviteV1, PairResponseInfoV1, PairResponsePlaintextV1,
};
use agentdeck_protocol::relay_v2::RELAY_PROTOCOL_VERSION;
use agentdeck_protocol::relay_v2::auth::{
    CertRole, Ed25519Signature, PublicKeyBytes, RelayGrant, SignedCertificate,
};
use agentdeck_protocol::relay_v2::id::{
    DeviceRouteId, GrantSerial, KeyDirectoryRevision, LinkGeneration, MachineRouteId, PairRouteId,
    RelayServerId, RootKeyId, TrustEpoch,
};
use agentdeck_protocol::runtime::{MachineRootFingerprint, RUNTIME_PROTOCOL_VERSION};
use uuid::Uuid;

pub const NOW_MS: u64 = 1_900_000_000_000;
pub const INSTALLATION_ID: Uuid = Uuid::from_bytes([0x11; 16]);
pub const MACHINE_ROUTE: MachineRouteId = MachineRouteId::from_bytes([0x21; 16]);
pub const DEVICE_ROUTE: DeviceRouteId = DeviceRouteId::from_bytes([0x25; 16]);
const PAIR_ROUTE: PairRouteId = PairRouteId::from_bytes([0x22; 16]);
const RELAY_SERVER: RelayServerId = RelayServerId::from_bytes([0x23; 16]);
const ROOT_KEY_ID: RootKeyId = RootKeyId::from_bytes([0x24; 16]);

pub const KEY_DIRECTORY_REVISION: u64 = 4;
pub const DEVICE_COMMAND_EPOCH: u64 = 5;
pub const DEVICE_REPLY_EPOCH: u64 = 7;
pub const DEVICE_COMMAND_KEY: [u8; 32] = [0x72; 32];
pub const DEVICE_REPLY_KEY: [u8; 32] = [0x73; 32];

pub struct DeterministicRng {
    seed: [u8; 32],
    counter: u64,
    block: [u8; 32],
    offset: usize,
}

impl DeterministicRng {
    pub fn new(seed: [u8; 32]) -> Self {
        Self {
            seed,
            counter: 0,
            block: [0; 32],
            offset: 32,
        }
    }

    fn fill(&mut self, output: &mut [u8]) {
        for byte in output {
            if self.offset == self.block.len() {
                let mut input = b"AgentDeck/RemoteRuntimeTestRng\0".to_vec();
                input.extend_from_slice(&self.seed);
                input.extend_from_slice(&self.counter.to_be_bytes());
                self.block = sha256(&input);
                self.counter += 1;
                self.offset = 0;
            }
            *byte = self.block[self.offset];
            self.offset += 1;
        }
    }
}

impl TryRng for DeterministicRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0; 4];
        self.fill(&mut bytes);
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0; 8];
        self.fill(&mut bytes);
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, output: &mut [u8]) -> Result<(), Self::Error> {
        self.fill(output);
        Ok(())
    }
}

impl TryCryptoRng for DeterministicRng {}

pub struct PanicRng;

impl TryRng for PanicRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        panic!("durable retry must not consume RNG")
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        panic!("durable retry must not consume RNG")
    }

    fn try_fill_bytes(&mut self, _output: &mut [u8]) -> Result<(), Self::Error> {
        panic!("durable retry must not consume RNG")
    }
}

impl TryCryptoRng for PanicRng {}

pub struct PairingFixture {
    invite: PairInviteV1,
    authorization: AuthorizationRequestV1,
}

impl PairingFixture {
    pub fn new() -> Self {
        let root = Self::root_signing_key();
        let data = Self::machine_data_signing_key();
        let root_fingerprint = sha256(&root.verifying_key().to_bytes());
        let mut data_certificate = SignedCertificate {
            subject_pubkey: PublicKeyBytes(data.verifying_key().to_bytes()),
            cert_role: CertRole::Data,
            generation: LinkGeneration::new(3),
            root_key_id: ROOT_KEY_ID,
            trust_epoch: TrustEpoch::new(2),
            not_after_ms: Some(NOW_MS + 600_000),
            signature: Ed25519Signature([0; 64]),
        };
        data_certificate.signature = sign_tbs(
            &root,
            &data_certificate.to_be_signed_v1(RELAY_SERVER, MACHINE_ROUTE, root_fingerprint),
        )
        .into();
        let (_invite_private, invite_public) = HpkePrivateKey::derive_keypair(&[0x33; 32]);
        Self {
            invite: PairInviteV1 {
                format_version: E2EE_FORMAT_VERSION,
                relay_protocol_version: RELAY_PROTOCOL_VERSION,
                pair_route: PAIR_ROUTE,
                invite_secret: [0x34; 32],
                invite_hpke_pubkey: PublicKeyBytes(
                    invite_public
                        .to_bytes()
                        .try_into()
                        .expect("X25519 public key"),
                ),
                wss_url: "wss://relay.example/".to_owned(),
                relay_server_id: RELAY_SERVER,
                current_spki_pin: [0x35; 32],
                next_spki_pin: [0x36; 32],
                expires_at_ms: NOW_MS + 300_000,
                machine_root_pubkey: PublicKeyBytes(root.verifying_key().to_bytes()),
                machine_root_fingerprint: root_fingerprint,
                data_sign_cert: data_certificate,
                machine_display_name: "Fixture Machine".to_owned(),
            },
            authorization: full_authorization(),
        }
    }

    pub fn machine_data_signing_key() -> SigningKey {
        SigningKey::from_seed(&[0x32; 32])
    }

    pub fn identity(&self) -> PairedMachineIdentity {
        PairedMachineIdentity::new(
            MachineRootFingerprint::from_bytes(self.invite.machine_root_fingerprint),
            MACHINE_ROUTE,
        )
    }

    pub fn promote(&self, store: &dyn RemoteKeyStore, state_root: &Path, seed: u8) -> VerifyingKey {
        let pending = PendingPairingCoordinator::new(store, INSTALLATION_ID);
        let mut request_rng = DeterministicRng::new([seed; 32]);
        let prepared = pending
            .prepare(&self.invite, &self.authorization, NOW_MS, &mut request_rng)
            .expect("prepare real PairRequest fixture");
        let device_sign = VerifyingKey::from_bytes(&prepared.device_sign_public_key())
            .expect("generated DeviceSign public key");
        let response = self.response_for(&prepared, [seed.wrapping_add(1); 32]);
        drop(prepared);
        let verified = pending
            .verify_response(&self.invite, &self.authorization, NOW_MS + 1, &response)
            .expect("verify real PairResponse fixture");
        let coordinator = PairedPromotionCoordinator::new(store, INSTALLATION_ID, state_root);
        let mut promotion_rng = DeterministicRng::new([seed.wrapping_add(2); 32]);
        drop(
            coordinator
                .promote(verified, &mut promotion_rng)
                .expect("promote paired fixture"),
        );
        device_sign
    }

    fn root_signing_key() -> SigningKey {
        SigningKey::from_seed(&[0x31; 32])
    }

    fn response_for(&self, prepared: &PreparedPairRequest, response_seed: [u8; 32]) -> Vec<u8> {
        let root = Self::root_signing_key();
        let data = Self::machine_data_signing_key();
        let root_fingerprint = self.invite.machine_root_fingerprint;
        let mut grant = RelayGrant {
            machine_route: MACHINE_ROUTE,
            device_route: DEVICE_ROUTE,
            device_sign_pubkey: PublicKeyBytes(prepared.device_sign_public_key()),
            grant_serial: GrantSerial::new(7),
            root_key_id: ROOT_KEY_ID,
            trust_epoch: TrustEpoch::new(2),
            signature: Ed25519Signature([0; 64]),
        };
        grant.signature = sign_tbs(
            &root,
            &grant.to_be_signed_v1(RELAY_SERVER, root_fingerprint),
        )
        .into();
        let authorization = sign_device_authorization(
            &root,
            RELAY_SERVER,
            &grant,
            DeviceAuthorizationV1 {
                format_version: E2EE_FORMAT_VERSION,
                grant_hash: grant.canonical_sha256(),
                machine_route: MACHINE_ROUTE,
                device_route: DEVICE_ROUTE,
                device_sign_fingerprint: sha256(&prepared.device_sign_public_key()),
                grant_serial: GrantSerial::new(7),
                device_hpke_pubkey: PublicKeyBytes(prepared.device_hpke_public_key()),
                capabilities: self.authorization.capabilities.clone(),
                permissions: self.authorization.permissions.clone(),
                root_key_id: ROOT_KEY_ID,
                trust_epoch: TrustEpoch::new(2),
                signature: Ed25519Signature([0; 64]),
            },
        )
        .expect("sign device authorization");
        let info = PairResponseInfoV1 {
            e2ee_format_version: E2EE_FORMAT_VERSION,
            runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
            relay_server_id: RELAY_SERVER,
            pair_route: PAIR_ROUTE,
            invite_hash: self.invite.canonical_sha256().expect("canonical invite"),
            expiry_ms: self.invite.expires_at_ms,
            request_hash: prepared.request_hash(),
            machine_route: MACHINE_ROUTE,
            device_route: DEVICE_ROUTE,
            grant_serial: GrantSerial::new(7),
            root_trust_epoch: TrustEpoch::new(2),
        };
        let revision = KeyDirectoryRevision::new(KEY_DIRECTORY_REVISION);
        let recipient =
            agentdeck_crypto::HpkePublicKey::from_bytes(&prepared.device_hpke_public_key())
                .expect("generated DeviceHPKE public key");
        let mut entry_rng = DeterministicRng::new([0x37; 32]);
        let mut entries = Vec::new();
        for (purpose, epoch, key_byte) in [
            (KeyPurpose::Catalog, 3_u64, 0x71_u8),
            (KeyPurpose::DeviceCommandTx, DEVICE_COMMAND_EPOCH, 0x72),
            (KeyPurpose::DeviceReplyTx, DEVICE_REPLY_EPOCH, 0x73),
        ] {
            let entry_info = KeyUpdateInfoV1 {
                e2ee_format_version: E2EE_FORMAT_VERSION,
                runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
                relay_server_id: RELAY_SERVER,
                machine_route: MACHINE_ROUTE,
                device_route: DEVICE_ROUTE,
                stream_route: None,
                grant_serial: GrantSerial::new(7),
                root_trust_epoch: TrustEpoch::new(2),
                key_directory_revision: revision,
                key_purpose: purpose,
                key_epoch: epoch,
            };
            entries.push(
                seal_key_directory_entry(
                    &recipient,
                    &entry_info,
                    &key_update_context(&entry_info),
                    &SecretAeadKey::from_bytes([key_byte; 32]),
                    &mut entry_rng,
                )
                .expect("seal key-directory entry"),
            );
        }
        let signer = MachineDataSignerBindingV1::from_certificate(&self.invite.data_sign_cert)
            .expect("valid data signer binding");
        let directory = sign_key_directory(
            &data,
            &signer,
            &KeyDirectorySignatureContextV1 {
                relay_server_id: RELAY_SERVER,
                machine_route: MACHINE_ROUTE,
                device_route: DEVICE_ROUTE,
                grant_serial: GrantSerial::new(7),
                root_trust_epoch: TrustEpoch::new(2),
            },
            KeyDirectoryV1 {
                revision,
                entries,
                signature: Ed25519Signature([0; 64]),
            },
        )
        .expect("sign key directory");
        let plaintext = PairResponsePlaintextV1 {
            format_version: E2EE_FORMAT_VERSION,
            request_hash: prepared.request_hash(),
            relay_grant: grant,
            device_authorization: authorization,
            key_directory: directory,
        };
        let mut response_rng = DeterministicRng::new(response_seed);
        seal_pair_response(
            &recipient,
            &info,
            &pairing_context(),
            &plaintext,
            PairResponseSealAuthority {
                machine_data_signing_key: &data,
                signer: &signer,
                machine_root_verifying_key: &root.verifying_key(),
            },
            &mut response_rng,
        )
        .expect("seal PairResponse")
        .canonical_bytes()
        .expect("canonical PairResponse")
    }
}

fn pairing_context() -> OuterContextV1 {
    OuterContextV1 {
        frame_kind: OuterFrameKind::PairResponse,
        relay_protocol_version: RELAY_PROTOCOL_VERSION,
        e2ee_format_version: E2EE_FORMAT_VERSION,
        machine_route: None,
        device_route: None,
        stream_route: None,
        request_route: None,
        pair_route: Some(PAIR_ROUTE),
        stream_generation: None,
        stream_cursor: None,
        stream_seq: None,
        message_key_epoch: 0,
    }
}

fn key_update_context(info: &KeyUpdateInfoV1) -> OuterContextV1 {
    OuterContextV1 {
        frame_kind: OuterFrameKind::KeyUpdate,
        relay_protocol_version: RELAY_PROTOCOL_VERSION,
        e2ee_format_version: E2EE_FORMAT_VERSION,
        machine_route: Some(info.machine_route),
        device_route: Some(info.device_route),
        stream_route: info.stream_route,
        request_route: None,
        pair_route: None,
        stream_generation: None,
        stream_cursor: None,
        stream_seq: None,
        message_key_epoch: info.key_epoch,
    }
}

fn full_authorization() -> AuthorizationRequestV1 {
    AuthorizationRequestV1 {
        format_version: E2EE_FORMAT_VERSION,
        device_display_name: "Persistent Remote CLI".to_owned(),
        capabilities: vec![
            AuthorizationCapabilityV1::Catalog,
            AuthorizationCapabilityV1::Conversation,
            AuthorizationCapabilityV1::Prompt,
            AuthorizationCapabilityV1::Command,
            AuthorizationCapabilityV1::Approval,
            AuthorizationCapabilityV1::Metadata,
            AuthorizationCapabilityV1::SelfRevocation,
        ],
        permissions: vec![
            AuthorizationPermissionV1::CatalogRead,
            AuthorizationPermissionV1::ConversationRead,
            AuthorizationPermissionV1::ConversationStart,
            AuthorizationPermissionV1::PromptSend,
            AuthorizationPermissionV1::CommandCancel,
            AuthorizationPermissionV1::ApprovalResolve,
            AuthorizationPermissionV1::ApprovalRetry,
            AuthorizationPermissionV1::MetadataWrite,
            AuthorizationPermissionV1::RevokeSelf,
        ],
    }
}
