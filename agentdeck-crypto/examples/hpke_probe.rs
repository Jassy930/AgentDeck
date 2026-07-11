//! Swift CryptoKit ↔ Rust interoperability probe used by P1.6 tests.
//!
//! JSON is carried over stdin/stdout so ephemeral private material never appears in argv.

use std::fs::File;
use std::io::{self, Read};

use agentdeck_crypto::{HpkeEnvelopeV1, HpkePrivateKey, hpke_open_base};
use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::{Value, json};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn main() {
    if let Err(error) = run() {
        eprintln!("hpke_probe: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let command = std::env::args().nth(1).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "expected command: generate | open | verify-signature",
        )
    })?;
    match command.as_str() {
        "generate" => generate_recipient(),
        "open" => open_swift_envelope(),
        "verify-signature" => verify_swift_signature(),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unknown command: {command}"),
        )
        .into()),
    }
}

fn generate_recipient() -> Result<()> {
    let mut ikm = [0u8; 32];
    File::open("/dev/urandom")?.read_exact(&mut ikm)?;
    let (private_key, public_key) = HpkePrivateKey::derive_keypair(&ikm);
    println!(
        "{}",
        json!({
            "recipientPrivateKeyHex": hex(&private_key.to_bytes()),
            "recipientPublicKeyHex": hex(&public_key.to_bytes()),
        })
    );
    Ok(())
}

fn open_swift_envelope() -> Result<()> {
    let request = read_request()?;
    let private_key =
        HpkePrivateKey::from_bytes(&decode_field(&request, "recipientPrivateKeyHex")?)?;
    let envelope = HpkeEnvelopeV1 {
        enc: decode_field(&request, "encHex")?,
        ciphertext: decode_field(&request, "ciphertextHex")?,
    };
    let plaintext = hpke_open_base(
        &private_key,
        &decode_field(&request, "infoHex")?,
        &decode_field(&request, "aadHex")?,
        &envelope,
    )?;
    println!("{}", json!({ "plaintextHex": hex(&plaintext) }));
    Ok(())
}

fn verify_swift_signature() -> Result<()> {
    let request = read_request()?;
    let public_key_bytes = fixed::<32>(decode_field(&request, "publicKeyHex")?, "publicKeyHex")?;
    let signature_bytes = fixed::<64>(decode_field(&request, "signatureHex")?, "signatureHex")?;
    let public_key = VerifyingKey::from_bytes(&public_key_bytes)?;
    let signature = Signature::from_bytes(&signature_bytes);
    let valid = public_key
        .verify_strict(&decode_field(&request, "messageHex")?, &signature)
        .is_ok();
    println!("{}", json!({ "valid": valid }));
    Ok(())
}

fn read_request() -> Result<Value> {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;
    Ok(serde_json::from_slice(&input)?)
}

fn decode_field(request: &Value, field: &'static str) -> Result<Vec<u8>> {
    let value = request
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, format!("missing {field}")))?;
    decode_hex(value, field)
}

fn decode_hex(value: &str, field: &'static str) -> Result<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{field} must have an even hex length"),
        )
        .into());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).expect("hex pairs are UTF-8");
            u8::from_str_radix(text, 16).map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("invalid {field}: {error}"),
                )
            })
        })
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(Into::into)
}

fn fixed<const N: usize>(bytes: Vec<u8>, field: &'static str) -> Result<[u8; N]> {
    let actual = bytes.len();
    bytes.try_into().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{field} must decode to {N} bytes, got {actual}"),
        )
        .into()
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
