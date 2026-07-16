#[path = "../src/runtime/store/sequence.rs"]
mod sequence;

use sequence::{SequenceError, SequenceScope, decode_sequence, encode_sequence, next_sequence};

#[test]
fn missing_high_water_allocates_zero() {
    let allocated = next_sequence(SequenceScope::CatalogRevision, None)
        .expect("empty catalog high-water allocates its first value");

    assert_eq!(allocated.value, 0);
    assert_eq!(allocated.encoded, "00000000000000000000");
}

#[test]
fn encoding_is_fixed_width_for_zero_single_and_double_digits_and_max() {
    let cases = [
        (0, "00000000000000000000"),
        (9, "00000000000000000009"),
        (10, "00000000000000000010"),
        (u64::MAX, "18446744073709551615"),
    ];

    for (value, expected) in cases {
        let encoded = encode_sequence(value);
        assert_eq!(encoded, expected);
        assert_eq!(encoded.len(), 20);
        assert_eq!(
            decode_sequence(SequenceScope::CommandSeq, &encoded)
                .expect("canonical sequence text must decode"),
            value
        );
    }
}

#[test]
fn next_sequence_decodes_then_uses_checked_add() {
    let allocated = next_sequence(SequenceScope::CommandSeq, Some("00000000000000000009"))
        .expect("nine has a successor");

    assert_eq!(allocated.value, 10);
    assert_eq!(allocated.encoded, "00000000000000000010");
}

#[test]
fn max_high_water_returns_scope_typed_exhaustion() {
    let error = next_sequence(SequenceScope::EventSeq, Some("18446744073709551615"))
        .expect_err("u64 max must never wrap");

    assert_eq!(
        error,
        SequenceError::Exhausted {
            scope: SequenceScope::EventSeq,
        }
    );
}

#[test]
fn decoding_rejects_noncanonical_or_out_of_range_text_with_scope() {
    let invalid = [
        "",
        "0000000000000000000",
        "000000000000000000000",
        "0000000000000000000x",
        " 0000000000000000000",
        "+0000000000000000000",
        "18446744073709551616",
        "００００００００００００００００００００",
    ];

    for value in invalid {
        assert_eq!(
            decode_sequence(SequenceScope::CommandSeq, value),
            Err(SequenceError::InvalidEncoding {
                scope: SequenceScope::CommandSeq,
            }),
            "unexpectedly accepted {value:?}"
        );
    }
}

#[test]
fn encoded_sequence_text_sorts_in_unsigned_numeric_order() {
    let values = [0, 1, 9, 10, 99, 100, u64::MAX - 1, u64::MAX];
    let encoded = values.map(encode_sequence);
    let mut lexicographic = encoded.clone();
    lexicographic.sort();

    assert_eq!(lexicographic, encoded);
}

#[test]
fn leader_start_time_uses_the_same_full_u64_codec_with_its_own_scope() {
    for scope in [
        SequenceScope::LeaderStartTime,
        SequenceScope::ConfigurationRevision,
        SequenceScope::EntryRevision,
    ] {
        assert_eq!(decode_sequence(scope, "18446744073709551615"), Ok(u64::MAX));
    }
}
