//! Minimal EdDSA (ed25519) JWT: sign / verify. No third-party JWT crate.
//!
//! Claims semantics: `iss` = device that signed and issued the token,
//! `sub` = device the token belongs to (the bearer). A device stores the token
//! its peer issued for it and presents it on every TCP connection.

use ed25519_dalek::{Signature, Verifier};
use serde::{Deserialize, Serialize};

use crate::identity::{b64d, b64e, now, verifying_key_from, Identity};

const HEADER: &str = r#"{"alg":"EdDSA","typ":"JWT"}"#;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Claims {
    pub iss: String,
    pub sub: String,
    pub iat: u64,
    /// 0 = no expiration.
    pub exp: u64,
}

pub fn sign(key: &Identity, sub: &str, expires_at: u64) -> String {
    let claims = Claims { iss: key.id.clone(), sub: sub.to_string(), iat: now(), exp: expires_at };
    let payload = serde_json::to_vec(&claims).expect("claims serialize");
    let input = format!("{}.{}", b64e(HEADER.as_bytes()), b64e(&payload));
    let sig = key.sign(input.as_bytes());
    format!("{input}.{}", b64e(&sig.to_bytes()))
}

/// Verify `token` was signed by `pubkey_b64`, issued by `expect_iss` (the peer) for `expect_sub` (us).
pub fn verify(
    pubkey_b64: &str,
    token: &str,
    expect_iss: &str,
    expect_sub: &str,
    at: u64,
) -> Result<Claims, String> {
    let mut parts = token.split('.');
    let (h, p, s) = match (parts.next(), parts.next(), parts.next()) {
        (Some(h), Some(p), Some(s)) => (h, p, s),
        _ => return Err("malformed token".into()),
    };
    if parts.next().is_some() {
        return Err("malformed token".into());
    }
    let sig_raw = b64d(s)?;
    let sig: [u8; 64] = sig_raw.try_into().map_err(|_| "bad signature length".to_string())?;
    let vk = verifying_key_from(pubkey_b64)?;
    vk.verify(format!("{h}.{p}").as_bytes(), &Signature::from_bytes(&sig))
        .map_err(|_| "bad signature".to_string())?;

    let payload = b64d(p)?;
    let claims: Claims = serde_json::from_slice(&payload).map_err(|e| format!("bad claims: {e}"))?;
    if claims.iss != expect_iss {
        return Err(format!("issuer mismatch ({} != {})", claims.iss, expect_iss));
    }
    if claims.sub != expect_sub {
        return Err("token is not for this device".into());
    }
    if claims.exp != 0 && claims.exp <= at {
        return Err("token expired".into());
    }
    Ok(claims)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::random_id;

    fn ident() -> Identity {
        Identity { id: random_id(), key: ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng) }
    }

    #[test]
    fn roundtrip() {
        let a = ident();
        let b = ident();
        let exp = now() + 3600;
        let t = sign(&a, &b.id, exp);
        let c = verify(&a.pubkey(), &t, &a.id, &b.id, now()).unwrap();
        assert_eq!(c.exp, exp);
        assert_eq!(c.iss, a.id);
    }

    #[test]
    fn rejects_tampering_and_misuse() {
        let a = ident();
        let b = ident();
        let c = ident();
        let t = sign(&a, &b.id, now() + 3600);

        // wrong signer
        assert!(verify(&b.pubkey(), &t, &a.id, &b.id, now()).is_err());
        // wrong audience
        assert!(verify(&a.pubkey(), &t, &a.id, &c.id, now()).is_err());
        // wrong issuer
        assert!(verify(&a.pubkey(), &t, &b.id, &b.id, now()).is_err());

        // tampered payload keeps old signature
        let mut parts: Vec<&str> = t.split('.').collect();
        let forged = b64e(&serde_json::to_vec(&Claims {
            iss: a.id.clone(),
            sub: c.id.clone(),
            iat: 0,
            exp: 0,
        })
        .unwrap());
        parts[1] = &forged;
        assert!(verify(&a.pubkey(), &parts.join("."), &a.id, &c.id, now()).is_err());
    }

    #[test]
    fn expiry() {
        let a = ident();
        let b = ident();
        let t = sign(&a, &b.id, now() - 1);
        assert!(verify(&a.pubkey(), &t, &a.id, &b.id, now()).is_err());
        let forever = sign(&a, &b.id, 0);
        assert!(verify(&a.pubkey(), &forever, &a.id, &b.id, now() + 10_000_000).is_ok());
    }
}
