use std::{collections::HashMap, time::SystemTime};

use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::SaltString};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use totp_rs::{Algorithm, TOTP};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

pub const DEFAULT_TOKEN_TTL_SECONDS: u64 = 24 * 60 * 60;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("invalid credential")]
    InvalidCredential,
    #[error("too many authentication attempts; retry later")]
    RateLimited,
    #[error("invalid token")]
    InvalidToken,
    #[error("token expired")]
    Expired,
    #[error("token has been revoked")]
    Revoked,
    #[error("authentication subsystem error")]
    Internal,
}

#[derive(Debug, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct Credential {
    #[serde(rename = "type")]
    pub kind: CredentialKind,
    pub value: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Zeroize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialKind {
    Password,
    Totp,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokenClaims {
    pub iss: String,
    pub aud: String,
    pub sub: String,
    pub jti: String,
    pub iat: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct TokenRecord {
    pub jti: String,
    pub issued_at: i64,
    pub expires_at: Option<i64>,
    pub revoked: bool,
}

pub struct AuthManager {
    password_hash: String,
    totp_secret: Option<Zeroizing<Vec<u8>>>,
    signing_key: SigningKey,
    instance_id: String,
    tokens: HashMap<String, TokenRecord>,
    failed_attempts: Vec<SystemTime>,
}

impl AuthManager {
    pub fn new(password_hash: String, totp_secret: Option<Zeroizing<Vec<u8>>>) -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self {
            password_hash,
            totp_secret,
            signing_key,
            instance_id: Uuid::new_v4().to_string(),
            tokens: HashMap::new(),
            failed_attempts: Vec::new(),
        }
    }

    pub fn public_key_base64(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.signing_key.verifying_key().as_bytes())
    }

    pub fn verify_credential(&mut self, credential: &Credential) -> Result<(), AuthError> {
        self.prune_attempts();
        if self.failed_attempts.len() >= 5 {
            return Err(AuthError::RateLimited);
        }
        let valid = match credential.kind {
            CredentialKind::Password => {
                let hash =
                    PasswordHash::new(&self.password_hash).map_err(|_| AuthError::Internal)?;
                Argon2::default()
                    .verify_password(credential.value.as_bytes(), &hash)
                    .is_ok()
            }
            CredentialKind::Totp => self
                .totp_secret
                .as_ref()
                .and_then(|secret| create_totp(secret).ok())
                .is_some_and(|totp| totp.check_current(credential.value.trim()).unwrap_or(false)),
        };
        if valid {
            self.failed_attempts.clear();
            Ok(())
        } else {
            self.failed_attempts.push(SystemTime::now());
            Err(AuthError::InvalidCredential)
        }
    }

    pub fn issue_token(
        &mut self,
        ttl_seconds: Option<u64>,
    ) -> Result<(String, TokenRecord), AuthError> {
        let now = Utc::now().timestamp();
        let expires_at = ttl_seconds
            .map(|ttl| {
                i64::try_from(ttl)
                    .ok()
                    .and_then(|v| now.checked_add(v))
                    .ok_or(AuthError::Internal)
            })
            .transpose()?;
        let claims = TokenClaims {
            iss: self.instance_id.clone(),
            aud: "sudoserver".into(),
            sub: "privileged-powershell".into(),
            jti: Uuid::new_v4().to_string(),
            iat: now,
            exp: expires_at,
        };
        let token = encode_jwt(&claims, &self.signing_key)?;
        let record = TokenRecord {
            jti: claims.jti.clone(),
            issued_at: now,
            expires_at,
            revoked: false,
        };
        self.tokens.insert(record.jti.clone(), record.clone());
        Ok((token, record))
    }

    pub fn verify_token(&self, token: &str) -> Result<TokenClaims, AuthError> {
        let claims = decode_jwt(token, &self.signing_key.verifying_key())?;
        if claims.iss != self.instance_id
            || claims.aud != "sudoserver"
            || claims.sub != "privileged-powershell"
        {
            return Err(AuthError::InvalidToken);
        }
        if claims.exp.is_some_and(|exp| Utc::now().timestamp() >= exp) {
            return Err(AuthError::Expired);
        }
        match self.tokens.get(&claims.jti) {
            Some(record) if record.revoked => Err(AuthError::Revoked),
            Some(_) => Ok(claims),
            None => Err(AuthError::InvalidToken),
        }
    }

    pub fn token_identity(&self, token: &str) -> Result<TokenClaims, AuthError> {
        let claims = decode_jwt(token, &self.signing_key.verifying_key())?;
        if claims.iss != self.instance_id || !self.tokens.contains_key(&claims.jti) {
            return Err(AuthError::InvalidToken);
        }
        Ok(claims)
    }

    pub fn revoke(&mut self, jti: &str) -> Result<(), AuthError> {
        let record = self.tokens.get_mut(jti).ok_or(AuthError::InvalidToken)?;
        record.revoked = true;
        Ok(())
    }

    pub fn list(&self) -> Vec<TokenRecord> {
        let mut records: Vec<_> = self.tokens.values().cloned().collect();
        records.sort_by_key(|record| -record.issued_at);
        records
    }

    fn prune_attempts(&mut self) {
        self.failed_attempts
            .retain(|at| at.elapsed().is_ok_and(|elapsed| elapsed.as_secs() < 60));
    }
}

pub fn hash_password(password: &[u8]) -> anyhow::Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    Ok(Argon2::default()
        .hash_password(password, &salt)
        .map_err(|error| anyhow::anyhow!(error.to_string()))?
        .to_string())
}

pub fn generate_totp_secret() -> Zeroizing<Vec<u8>> {
    let mut secret = vec![0_u8; 32];
    OsRng.fill_bytes(&mut secret);
    Zeroizing::new(secret)
}

pub fn create_totp(secret: &[u8]) -> anyhow::Result<TOTP> {
    TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret.to_vec(),
        Some("SudoServer".into()),
        "local-admin".into(),
    )
    .map_err(|error| anyhow::anyhow!(error.to_string()))
}

fn encode_jwt(claims: &TokenClaims, key: &SigningKey) -> Result<String, AuthError> {
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"EdDSA","typ":"JWT"}"#);
    let payload =
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).map_err(|_| AuthError::Internal)?);
    let message = format!("{header}.{payload}");
    let signature = key.sign(message.as_bytes());
    Ok(format!(
        "{message}.{}",
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    ))
}

fn decode_jwt(token: &str, key: &VerifyingKey) -> Result<TokenClaims, AuthError> {
    let mut parts = token.split('.');
    let header = parts.next().ok_or(AuthError::InvalidToken)?;
    let payload = parts.next().ok_or(AuthError::InvalidToken)?;
    let signature = parts.next().ok_or(AuthError::InvalidToken)?;
    if parts.next().is_some() {
        return Err(AuthError::InvalidToken);
    }
    let decoded_header = URL_SAFE_NO_PAD
        .decode(header)
        .map_err(|_| AuthError::InvalidToken)?;
    let header_json: serde_json::Value =
        serde_json::from_slice(&decoded_header).map_err(|_| AuthError::InvalidToken)?;
    if header_json.get("alg").and_then(|value| value.as_str()) != Some("EdDSA") {
        return Err(AuthError::InvalidToken);
    }
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(signature)
        .map_err(|_| AuthError::InvalidToken)?;
    let signature = Signature::from_slice(&signature_bytes).map_err(|_| AuthError::InvalidToken)?;
    key.verify(format!("{header}.{payload}").as_bytes(), &signature)
        .map_err(|_| AuthError::InvalidToken)?;
    let decoded_payload = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| AuthError::InvalidToken)?;
    serde_json::from_slice(&decoded_payload).map_err(|_| AuthError::InvalidToken)
}

pub fn fingerprint_token(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    URL_SAFE_NO_PAD.encode(&digest[..12])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manager() -> AuthManager {
        AuthManager::new(hash_password(b"correct horse").unwrap(), None)
    }

    #[test]
    fn password_verification_and_rate_limit() {
        let mut auth = manager();
        let good = Credential {
            kind: CredentialKind::Password,
            value: "correct horse".into(),
        };
        assert!(auth.verify_credential(&good).is_ok());
        for _ in 0..5 {
            let bad = Credential {
                kind: CredentialKind::Password,
                value: "wrong".into(),
            };
            assert!(matches!(
                auth.verify_credential(&bad),
                Err(AuthError::InvalidCredential)
            ));
        }
        assert!(matches!(
            auth.verify_credential(&good),
            Err(AuthError::RateLimited)
        ));
    }

    #[test]
    fn token_is_signed_expires_and_revokes() {
        let mut auth = manager();
        let (token, record) = auth.issue_token(Some(60)).unwrap();
        assert_eq!(auth.verify_token(&token).unwrap().jti, record.jti);
        let mut tampered = token.clone();
        tampered.push('x');
        assert!(matches!(
            auth.verify_token(&tampered),
            Err(AuthError::InvalidToken)
        ));
        auth.revoke(&record.jti).unwrap();
        assert!(matches!(auth.verify_token(&token), Err(AuthError::Revoked)));
    }

    #[test]
    fn signing_keys_are_ephemeral() {
        let mut first = manager();
        let second = manager();
        let (token, _) = first.issue_token(None).unwrap();
        assert!(second.verify_token(&token).is_err());
        assert_ne!(first.public_key_base64(), second.public_key_base64());
    }

    #[test]
    fn totp_is_compatible_with_standard_sha1_six_digit_apps() {
        let secret = generate_totp_secret();
        let totp = create_totp(&secret).unwrap();
        let code = totp.generate_current().unwrap();
        assert!(totp.check_current(&code).unwrap());
        assert!(totp.get_url().starts_with("otpauth://totp/"));
    }
}
