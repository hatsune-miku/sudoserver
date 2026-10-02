use std::{collections::HashMap, time::SystemTime};

use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::SaltString};
use chrono::Utc;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use totp_rs::{Algorithm, TOTP};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

pub const DEFAULT_TOKEN_TTL_SECONDS: u64 = 24 * 60 * 60;
const TOKEN_LENGTH: usize = 22;
const TOKEN_ALPHABET: &[u8; 62] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

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

#[derive(Clone, Debug)]
pub struct TokenAuthorization {
    pub id: String,
    pub expires_at: Option<i64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct TokenRecord {
    pub id: String,
    pub issued_at: i64,
    pub expires_at: Option<i64>,
    pub revoked: bool,
}

pub struct AuthManager {
    password_hash: String,
    totp_secret: Option<Zeroizing<Vec<u8>>>,
    tokens: HashMap<[u8; 32], TokenRecord>,
    token_hashes_by_id: HashMap<String, [u8; 32]>,
    failed_attempts: Vec<SystemTime>,
}

impl AuthManager {
    pub fn new(password_hash: String, totp_secret: Option<Zeroizing<Vec<u8>>>) -> Self {
        Self {
            password_hash,
            totp_secret,
            tokens: HashMap::new(),
            token_hashes_by_id: HashMap::new(),
            failed_attempts: Vec::new(),
        }
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
        let (token, token_hash) = loop {
            let token = generate_token();
            let token_hash = hash_token(&token);
            if !self.tokens.contains_key(&token_hash) {
                break (token, token_hash);
            }
        };
        let record = TokenRecord {
            id: Uuid::new_v4().to_string(),
            issued_at: now,
            expires_at,
            revoked: false,
        };
        self.token_hashes_by_id
            .insert(record.id.clone(), token_hash);
        self.tokens.insert(token_hash, record.clone());
        Ok((token, record))
    }

    pub fn verify_token(&self, token: &str) -> Result<TokenAuthorization, AuthError> {
        let record = self.token_record(token)?;
        if record.revoked {
            return Err(AuthError::Revoked);
        }
        if record
            .expires_at
            .is_some_and(|expiry| Utc::now().timestamp() >= expiry)
        {
            return Err(AuthError::Expired);
        }
        Ok(TokenAuthorization {
            id: record.id.clone(),
            expires_at: record.expires_at,
        })
    }

    pub fn token_identity(&self, token: &str) -> Result<TokenAuthorization, AuthError> {
        let record = self.token_record(token)?;
        Ok(TokenAuthorization {
            id: record.id.clone(),
            expires_at: record.expires_at,
        })
    }

    pub fn revoke(&mut self, id: &str) -> Result<(), AuthError> {
        let token_hash = self
            .token_hashes_by_id
            .get(id)
            .ok_or(AuthError::InvalidToken)?;
        let record = self.tokens.get_mut(token_hash).ok_or(AuthError::Internal)?;
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

    fn token_record(&self, token: &str) -> Result<&TokenRecord, AuthError> {
        if token.len() != TOKEN_LENGTH || !token.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
            return Err(AuthError::InvalidToken);
        }
        self.tokens
            .get(&hash_token(token))
            .ok_or(AuthError::InvalidToken)
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
        Some("localshelld".into()),
        "local-admin".into(),
    )
    .map_err(|error| anyhow::anyhow!(error.to_string()))
}

fn generate_token() -> String {
    let mut token = String::with_capacity(TOKEN_LENGTH);
    let mut random = [0_u8; 32];
    while token.len() < TOKEN_LENGTH {
        OsRng.fill_bytes(&mut random);
        for byte in random {
            // 248 is the largest multiple of 62 that fits in one byte. Rejecting
            // larger values keeps every character equally likely.
            if byte < 248 {
                token.push(TOKEN_ALPHABET[usize::from(byte % 62)] as char);
                if token.len() == TOKEN_LENGTH {
                    break;
                }
            }
        }
    }
    token
}

fn hash_token(token: &str) -> [u8; 32] {
    let digest = Sha256::digest(token.as_bytes());
    digest.into()
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
    fn token_is_short_opaque_and_revocable() {
        let mut auth = manager();
        let (token, record) = auth.issue_token(Some(60)).unwrap();
        assert_eq!(token.len(), TOKEN_LENGTH);
        assert!(token.bytes().all(|byte| byte.is_ascii_alphanumeric()));
        assert_eq!(auth.verify_token(&token).unwrap().id, record.id);
        let mut tampered = token.clone();
        tampered.replace_range(..1, if token.starts_with('A') { "B" } else { "A" });
        assert!(matches!(
            auth.verify_token(&tampered),
            Err(AuthError::InvalidToken)
        ));
        auth.revoke(&record.id).unwrap();
        assert!(matches!(auth.verify_token(&token), Err(AuthError::Revoked)));
    }

    #[test]
    fn tokens_are_process_local() {
        let mut first = manager();
        let second = manager();
        let (token, _) = first.issue_token(None).unwrap();
        assert!(second.verify_token(&token).is_err());
    }

    #[test]
    fn token_expiry_is_enforced_from_server_metadata() {
        let mut auth = manager();
        let (token, _) = auth.issue_token(Some(0)).unwrap();
        assert!(matches!(auth.verify_token(&token), Err(AuthError::Expired)));
        assert!(auth.token_identity(&token).is_ok());
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
