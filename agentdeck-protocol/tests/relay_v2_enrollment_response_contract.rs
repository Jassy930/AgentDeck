//! Machine enrollment response 的 validated deterministic canonical 合同。

use agentdeck_protocol::relay_v2::enrollment::{
    MachineEnrollmentResponseError, MachineEnrollmentResponseV1,
};
use agentdeck_protocol::relay_v2::{MachineRouteId, RelayServerId};

fn response() -> MachineEnrollmentResponseV1 {
    MachineEnrollmentResponseV1::new(
        RelayServerId::from_bytes([0x11; 16]),
        MachineRouteId::from_bytes([0x22; 16]),
        0x0102_0304_0506_0708,
        [0x33; 32],
    )
    .expect("construct valid enrollment response")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn enrollment_response_canonical_bytes_and_hash_are_golden_and_deterministic() {
    let response = response();
    let canonical = response
        .canonical_bytes()
        .expect("encode validated enrollment response");
    assert_eq!(
        hex(&canonical),
        "4167656e744465636b2f4d616368696e65456e726f6c6c6d656e74526573706f6e7365563100000000101111111111111111111111111111111100000010222222222222222222222222222222220102030405060708000000203333333333333333333333333333333333333333333333333333333333333333",
        "enrollment response canonical bytes drifted"
    );
    assert_eq!(
        hex(&response
            .canonical_sha256()
            .expect("hash validated enrollment response")),
        "473b596bf44b556d9cd4faac2725d730f2726f522c1528a607875fbab7f31816",
        "enrollment response canonical hash drifted"
    );
    assert_eq!(
        response.canonical_bytes().unwrap(),
        response.canonical_bytes().unwrap()
    );
    assert_eq!(
        response.canonical_sha256().unwrap(),
        response.canonical_sha256().unwrap()
    );
}

#[test]
fn enrollment_response_canonical_hash_binds_every_field() {
    let original = response();
    let original_hash = original.canonical_sha256().unwrap();

    let mut tampered = original.clone();
    tampered.relay_server_id = RelayServerId::from_bytes([0x12; 16]);
    assert_ne!(tampered.canonical_sha256().unwrap(), original_hash);

    let mut tampered = original.clone();
    tampered.machine_route = MachineRouteId::from_bytes([0x23; 16]);
    assert_ne!(tampered.canonical_sha256().unwrap(), original_hash);

    let mut tampered = original.clone();
    tampered.trust_epoch += 1;
    assert_ne!(tampered.canonical_sha256().unwrap(), original_hash);

    let mut tampered = original;
    tampered.receipt_hash[0] ^= 1;
    assert_ne!(tampered.canonical_sha256().unwrap(), original_hash);
}

#[test]
fn enrollment_response_rejects_every_all_zero_bound_field() {
    let valid = response();
    for (response, expected) in [
        (
            MachineEnrollmentResponseV1 {
                relay_server_id: RelayServerId::from_bytes([0; 16]),
                ..valid.clone()
            },
            MachineEnrollmentResponseError::ZeroBoundField("relayServerId"),
        ),
        (
            MachineEnrollmentResponseV1 {
                machine_route: MachineRouteId::from_bytes([0; 16]),
                ..valid.clone()
            },
            MachineEnrollmentResponseError::ZeroBoundField("machineRoute"),
        ),
        (
            MachineEnrollmentResponseV1 {
                trust_epoch: 0,
                ..valid.clone()
            },
            MachineEnrollmentResponseError::ZeroBoundField("trustEpoch"),
        ),
        (
            MachineEnrollmentResponseV1 {
                receipt_hash: [0; 32],
                ..valid
            },
            MachineEnrollmentResponseError::ZeroBoundField("receiptHash"),
        ),
    ] {
        assert_eq!(response.validate().unwrap_err(), expected);
        assert_eq!(response.canonical_bytes().unwrap_err(), expected);
        assert_eq!(response.canonical_sha256().unwrap_err(), expected);
    }

    assert_eq!(
        MachineEnrollmentResponseV1::new(
            RelayServerId::from_bytes([0; 16]),
            MachineRouteId::from_bytes([0x22; 16]),
            1,
            [0x33; 32],
        )
        .unwrap_err(),
        MachineEnrollmentResponseError::ZeroBoundField("relayServerId")
    );
}
