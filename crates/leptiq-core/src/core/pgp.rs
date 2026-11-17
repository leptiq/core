//! Minimal OpenPGP helpers: derive the public key and fingerprint from an
//! armored (passphrase-locked) private key. Public parts are not encrypted,
//! so no passphrase is needed.

use pgp::composed::{ArmorOptions, Deserializable, SignedPublicKey, SignedSecretKey};
use pgp::types::KeyDetails;

pub struct KeyInfo {
    pub public_armored: String,
    pub fingerprint: String,
    pub sha256_fingerprints: Vec<String>,
}

pub fn inspect_private(armored: &str) -> Option<KeyInfo> {
    let (key, _) = SignedSecretKey::from_string(armored).ok()?;
    let public = key.to_public_key();
    Some(describe_public(&public))
}

pub fn inspect_public(armored: &str) -> Option<KeyInfo> {
    let (key, _) = SignedPublicKey::from_string(armored).ok()?;
    Some(describe_public(&key))
}

fn describe_public(public: &SignedPublicKey) -> KeyInfo {
    let fingerprint = hex::encode(public.fingerprint().as_bytes());
    let mut sha256 = vec![sha256_hex_of_key(public)];
    for sub in &public.public_subkeys {
        sha256.push(hex::encode(sub.key.fingerprint().as_bytes()));
    }
    KeyInfo {
        public_armored: public
            .to_armored_string(ArmorOptions::default())
            .unwrap_or_default(),
        fingerprint,
        sha256_fingerprints: sha256,
    }
}

fn sha256_hex_of_key(public: &SignedPublicKey) -> String {
    use sha2::{Digest, Sha256};
    let mut buf = Vec::new();
    let _ = pgp::ser::Serialize::to_writer(&public.primary_key, &mut buf);
    hex::encode(Sha256::digest(&buf))
}
