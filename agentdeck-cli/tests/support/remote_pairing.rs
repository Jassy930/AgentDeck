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
    RelayServerId, RootKeyId, StreamRouteId, TrustEpoch,
};
use agentdeck_protocol::runtime::{MachineRootFingerprint, RUNTIME_PROTOCOL_VERSION};
use uuid::Uuid;

pub const NOW_MS: u64 = 1_900_000_000_000;
pub const INSTALLATION_ID: Uuid = Uuid::from_bytes([0x11; 16]);
pub const MACHINE_ROUTE: MachineRouteId = MachineRouteId::from_bytes([0x21; 16]);
pub const DEVICE_ROUTE: DeviceRouteId = DeviceRouteId::from_bytes([0x25; 16]);
const PAIR_ROUTE: PairRouteId = PairRouteId::from_bytes([0x22; 16]);
pub const RELAY_SERVER: RelayServerId = RelayServerId::from_bytes([0x23; 16]);
pub const ROOT_KEY_ID: RootKeyId = RootKeyId::from_bytes([0x24; 16]);

pub const KEY_DIRECTORY_REVISION: u64 = 4;
pub const CATALOG_EPOCH: u64 = 3;
pub const CONVERSATION_EPOCH: u64 = 9;
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
    root_signing_seed: [u8; 32],
    machine_data_signing_seed: [u8; 32],
    machine_route: MachineRouteId,
    device_route: DeviceRouteId,
    conversation_stream_routes: Vec<StreamRouteId>,
}

impl PairingFixture {
    pub fn new() -> Self {
        Self::new_with_identity(
            [0x31; 32],
            [0x32; 32],
            MACHINE_ROUTE,
            DEVICE_ROUTE,
            PAIR_ROUTE,
            ROOT_KEY_ID,
            [0x33; 32],
            [0x34; 32],
            [0x35; 32],
            [0x36; 32],
            "Fixture Machine".to_owned(),
        )
    }

    /// 同一 installation 下构造另一台 cryptographically independent machine fixture。
    /// 默认 [`Self::new`] 的全部字节保持不变；此入口只供需要多 machine 全库语义的测试使用。
    pub fn new_distinct(identity_seed: u8) -> Self {
        Self::new_with_identity(
            [identity_seed; 32],
            [identity_seed.wrapping_add(1); 32],
            MachineRouteId::from_bytes([identity_seed.wrapping_add(2); 16]),
            DeviceRouteId::from_bytes([identity_seed.wrapping_add(3); 16]),
            PairRouteId::from_bytes([identity_seed.wrapping_add(4); 16]),
            RootKeyId::from_bytes([identity_seed.wrapping_add(5); 16]),
            [identity_seed.wrapping_add(6); 32],
            [identity_seed.wrapping_add(7); 32],
            [identity_seed.wrapping_add(8); 32],
            [identity_seed.wrapping_add(9); 32],
            format!("Fixture Machine {identity_seed:02x}"),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new_with_identity(
        root_signing_seed: [u8; 32],
        machine_data_signing_seed: [u8; 32],
        machine_route: MachineRouteId,
        device_route: DeviceRouteId,
        pair_route: PairRouteId,
        root_key_id: RootKeyId,
        invite_hpke_seed: [u8; 32],
        invite_secret: [u8; 32],
        current_spki_pin: [u8; 32],
        next_spki_pin: [u8; 32],
        machine_display_name: String,
    ) -> Self {
        let root = SigningKey::from_seed(&root_signing_seed);
        let data = SigningKey::from_seed(&machine_data_signing_seed);
        let root_fingerprint = sha256(&root.verifying_key().to_bytes());
        let mut data_certificate = SignedCertificate {
            subject_pubkey: PublicKeyBytes(data.verifying_key().to_bytes()),
            cert_role: CertRole::Data,
            generation: LinkGeneration::new(3),
            root_key_id,
            trust_epoch: TrustEpoch::new(2),
            not_after_ms: Some(NOW_MS + 600_000),
            signature: Ed25519Signature([0; 64]),
        };
        data_certificate.signature = sign_tbs(
            &root,
            &data_certificate.to_be_signed_v1(RELAY_SERVER, machine_route, root_fingerprint),
        )
        .into();
        let (_invite_private, invite_public) = HpkePrivateKey::derive_keypair(&invite_hpke_seed);
        Self {
            invite: PairInviteV1 {
                format_version: E2EE_FORMAT_VERSION,
                relay_protocol_version: RELAY_PROTOCOL_VERSION,
                pair_route,
                invite_secret,
                invite_hpke_pubkey: PublicKeyBytes(
                    invite_public
                        .to_bytes()
                        .try_into()
                        .expect("X25519 public key"),
                ),
                wss_url: "wss://relay.example/".to_owned(),
                relay_server_id: RELAY_SERVER,
                current_spki_pin,
                next_spki_pin,
                expires_at_ms: NOW_MS + 300_000,
                machine_root_pubkey: PublicKeyBytes(root.verifying_key().to_bytes()),
                machine_root_fingerprint: root_fingerprint,
                data_sign_cert: data_certificate,
                machine_display_name,
            },
            authorization: full_authorization(),
            root_signing_seed,
            machine_data_signing_seed,
            machine_route,
            device_route,
            conversation_stream_routes: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_conversation_stream(mut self, stream_route: StreamRouteId) -> Self {
        self.conversation_stream_routes.push(stream_route);
        self
    }

    #[must_use]
    pub fn without_catalog_authorization(mut self) -> Self {
        self.authorization
            .capabilities
            .retain(|capability| *capability != AuthorizationCapabilityV1::Catalog);
        self.authorization
            .permissions
            .retain(|permission| *permission != AuthorizationPermissionV1::CatalogRead);
        self
    }

    #[must_use]
    pub fn without_catalog_read_permission(mut self) -> Self {
        self.authorization
            .permissions
            .retain(|permission| *permission != AuthorizationPermissionV1::CatalogRead);
        self
    }

    pub fn machine_data_signing_key() -> SigningKey {
        SigningKey::from_seed(&[0x32; 32])
    }

    pub fn invite(&self) -> &PairInviteV1 {
        &self.invite
    }

    pub fn authorization(&self) -> &AuthorizationRequestV1 {
        &self.authorization
    }

    pub fn identity(&self) -> PairedMachineIdentity {
        PairedMachineIdentity::new(
            MachineRootFingerprint::from_bytes(self.invite.machine_root_fingerprint),
            self.machine_route,
        )
    }

    pub fn machine_route(&self) -> MachineRouteId {
        self.machine_route
    }

    pub fn device_route(&self) -> DeviceRouteId {
        self.device_route
    }

    pub fn root_key_id(&self) -> RootKeyId {
        self.invite.data_sign_cert.root_key_id
    }

    pub fn fixture_root_signing_key(&self) -> SigningKey {
        SigningKey::from_seed(&self.root_signing_seed)
    }

    pub fn promote(&self, store: &dyn RemoteKeyStore, state_root: &Path, seed: u8) -> VerifyingKey {
        self.promote_for_installation(store, state_root, INSTALLATION_ID, seed)
    }

    pub fn promote_for_installation(
        &self,
        store: &dyn RemoteKeyStore,
        state_root: &Path,
        installation_id: Uuid,
        seed: u8,
    ) -> VerifyingKey {
        let pending = PendingPairingCoordinator::new(store, installation_id);
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
        let coordinator = PairedPromotionCoordinator::new(store, installation_id, state_root);
        let mut promotion_rng = DeterministicRng::new([seed.wrapping_add(2); 32]);
        drop(
            coordinator
                .promote(verified, &mut promotion_rng)
                .expect("promote paired fixture"),
        );
        device_sign
    }

    pub fn root_signing_key() -> SigningKey {
        SigningKey::from_seed(&[0x31; 32])
    }

    pub fn response_for(&self, prepared: &PreparedPairRequest, response_seed: [u8; 32]) -> Vec<u8> {
        let root = self.fixture_root_signing_key();
        let data = SigningKey::from_seed(&self.machine_data_signing_seed);
        let root_fingerprint = self.invite.machine_root_fingerprint;
        let mut grant = RelayGrant {
            machine_route: self.machine_route,
            device_route: self.device_route,
            device_sign_pubkey: PublicKeyBytes(prepared.device_sign_public_key()),
            grant_serial: GrantSerial::new(7),
            root_key_id: self.root_key_id(),
            trust_epoch: TrustEpoch::new(2),
            signature: Ed25519Signature([0; 64]),
        };
        grant.signature = sign_tbs(
            &root,
            &grant.to_be_signed_v1(self.invite.relay_server_id, root_fingerprint),
        )
        .into();
        let authorization = sign_device_authorization(
            &root,
            self.invite.relay_server_id,
            &grant,
            DeviceAuthorizationV1 {
                format_version: E2EE_FORMAT_VERSION,
                grant_hash: grant.canonical_sha256(),
                machine_route: self.machine_route,
                device_route: self.device_route,
                device_sign_fingerprint: sha256(&prepared.device_sign_public_key()),
                grant_serial: GrantSerial::new(7),
                device_hpke_pubkey: PublicKeyBytes(prepared.device_hpke_public_key()),
                capabilities: self.authorization.capabilities.clone(),
                permissions: self.authorization.permissions.clone(),
                root_key_id: self.root_key_id(),
                trust_epoch: TrustEpoch::new(2),
                signature: Ed25519Signature([0; 64]),
            },
        )
        .expect("sign device authorization");
        let info = PairResponseInfoV1 {
            e2ee_format_version: E2EE_FORMAT_VERSION,
            runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
            relay_server_id: self.invite.relay_server_id,
            pair_route: self.invite.pair_route,
            invite_hash: self.invite.canonical_sha256().expect("canonical invite"),
            expiry_ms: self.invite.expires_at_ms,
            request_hash: prepared.request_hash(),
            machine_route: self.machine_route,
            device_route: self.device_route,
            grant_serial: GrantSerial::new(7),
            root_trust_epoch: TrustEpoch::new(2),
        };
        let revision = KeyDirectoryRevision::new(KEY_DIRECTORY_REVISION);
        let recipient =
            agentdeck_crypto::HpkePublicKey::from_bytes(&prepared.device_hpke_public_key())
                .expect("generated DeviceHPKE public key");
        let mut entry_rng = DeterministicRng::new([0x37; 32]);
        let mut entries = Vec::new();
        let catalog_info = KeyUpdateInfoV1 {
            e2ee_format_version: E2EE_FORMAT_VERSION,
            runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
            relay_server_id: self.invite.relay_server_id,
            machine_route: self.machine_route,
            device_route: self.device_route,
            stream_route: None,
            grant_serial: GrantSerial::new(7),
            root_trust_epoch: TrustEpoch::new(2),
            key_directory_revision: revision,
            key_purpose: KeyPurpose::Catalog,
            key_epoch: CATALOG_EPOCH,
        };
        entries.push(
            seal_key_directory_entry(
                &recipient,
                &catalog_info,
                &key_update_context(&catalog_info),
                &SecretAeadKey::from_bytes([0x71; 32]),
                &mut entry_rng,
            )
            .expect("seal key-directory entry"),
        );
        for (index, stream_route) in self.conversation_stream_routes.iter().copied().enumerate() {
            let entry_info = KeyUpdateInfoV1 {
                e2ee_format_version: E2EE_FORMAT_VERSION,
                runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
                relay_server_id: self.invite.relay_server_id,
                machine_route: self.machine_route,
                device_route: self.device_route,
                stream_route: Some(stream_route),
                grant_serial: GrantSerial::new(7),
                root_trust_epoch: TrustEpoch::new(2),
                key_directory_revision: revision,
                key_purpose: KeyPurpose::ConversationDek,
                key_epoch: CONVERSATION_EPOCH,
            };
            let key_byte = 0x74_u8.wrapping_add(u8::try_from(index).expect("test stream count"));
            entries.push(
                seal_key_directory_entry(
                    &recipient,
                    &entry_info,
                    &key_update_context(&entry_info),
                    &SecretAeadKey::from_bytes([key_byte; 32]),
                    &mut entry_rng,
                )
                .expect("seal conversation key-directory entry"),
            );
        }
        for (purpose, epoch, key_byte) in [
            (KeyPurpose::DeviceCommandTx, DEVICE_COMMAND_EPOCH, 0x72),
            (KeyPurpose::DeviceReplyTx, DEVICE_REPLY_EPOCH, 0x73),
        ] {
            let entry_info = KeyUpdateInfoV1 {
                e2ee_format_version: E2EE_FORMAT_VERSION,
                runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
                relay_server_id: self.invite.relay_server_id,
                machine_route: self.machine_route,
                device_route: self.device_route,
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
                relay_server_id: self.invite.relay_server_id,
                machine_route: self.machine_route,
                device_route: self.device_route,
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
            &pairing_context(self.invite.pair_route),
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

fn pairing_context(pair_route: PairRouteId) -> OuterContextV1 {
    OuterContextV1 {
        frame_kind: OuterFrameKind::PairResponse,
        relay_protocol_version: RELAY_PROTOCOL_VERSION,
        e2ee_format_version: E2EE_FORMAT_VERSION,
        machine_route: None,
        device_route: None,
        stream_route: None,
        request_route: None,
        pair_route: Some(pair_route),
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
