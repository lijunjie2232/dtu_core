//! Device identity: random id + ed25519 keypair, persisted in identity.json.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

pub fn b64e(b: &[u8]) -> String {
    B64.encode(b)
}

pub fn b64d(s: &str) -> Result<Vec<u8>, String> {
    B64.decode(s.trim()).map_err(|e| format!("bad base64: {e}"))
}

/// 128-bit random device id, base64url (22 chars).
pub fn random_id() -> String {
    let mut rng = rand::thread_rng();
    let bytes: Vec<u8> = (0..16).map(|_| rng.gen()).collect();
    b64e(&bytes)
}

/// Short human-typed token, no ambiguous characters (no 0/O/1/I).
pub fn random_code(len: usize) -> String {
    const CHARSET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut rng = rand::thread_rng();
    (0..len)
        .map(|_| CHARSET[rng.gen_range(0..CHARSET.len())] as char)
        .collect()
}

#[derive(Serialize, Deserialize)]
struct Stored {
    id: String,
    secret: String,
    created_at: u64,
}

#[derive(Clone)]
pub struct Identity {
    pub id: String,
    pub key: SigningKey,
}

impl Identity {
    pub fn load_or_create() -> Result<Self, String> {
        Self::load_or_create_at(&crate::cfg::file("identity.json"))
    }

    pub fn load_or_create_at(path: &std::path::Path) -> Result<Self, String> {
        if let Some(s) = crate::cfg::read_json::<Stored>(path) {
            let raw = b64d(&s.secret)?;
            let arr: [u8; 32] = raw.try_into().map_err(|_| "identity.json: bad secret length")?;
            return Ok(Self { id: s.id, key: SigningKey::from_bytes(&arr) });
        }
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let id = random_id();
        let stored = Stored { id: id.clone(), secret: b64e(&key.to_bytes()), created_at: now() };
        crate::cfg::write_json(path, &stored).map_err(|e| format!("write identity.json: {e}"))?;
        Ok(Self { id, key })
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }

    pub fn pubkey(&self) -> String {
        b64e(&self.verifying_key().to_bytes())
    }

    pub fn sign(&self, msg: &[u8]) -> Signature {
        self.key.sign(msg)
    }
}

pub fn verifying_key_from(pubkey_b64: &str) -> Result<VerifyingKey, String> {
    let raw = b64d(pubkey_b64)?;
    let arr: [u8; 32] = raw.try_into().map_err(|_| "bad public key length".to_string())?;
    VerifyingKey::from_bytes(&arr).map_err(|e| format!("bad public key: {e}"))
}

/// Constant-time-ish comparison for secrets (length leak is fine here, values are fixed-size).
pub fn ct_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_and_codes_are_usable() {
        let id = random_id();
        assert_eq!(id.len(), 22);
        assert_ne!(id, random_id());
        let code = random_code(8);
        assert_eq!(code.len(), 8);
        assert!(code.chars().all(|c| c.is_ascii_alphanumeric()));
        assert!(ct_eq("ABC", "ABC"));
        assert!(!ct_eq("ABC", "ABD"));
        assert!(!ct_eq("ABC", "AB"));
    }

    #[test]
    fn identity_roundtrip_via_file() {
        let dir = std::env::temp_dir().join(format!("dtu-ident-{}", random_id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("identity.json");
        let a = Identity::load_or_create_at(&path).unwrap();
        let b = Identity::load_or_create_at(&path).unwrap();
        assert_eq!(a.id, b.id);
        assert_eq!(a.pubkey(), b.pubkey());
        let _ = std::fs::remove_dir_all(dir);
    }
}
