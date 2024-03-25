use crate::crypto::error::CryptoError;
use dotenv;
use rand::rngs::OsRng;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs8::{DecodePublicKey, EncodePublicKey, LineEnding};
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::time::{SystemTime, UNIX_EPOCH};
use std::usize;

/// Represents a RSA key pair with a unique identifier and expiry timestamp.
#[derive(Serialize, Deserialize, Clone)]
pub struct KeyPair {
    /// A unique identifier for the key pair.
    pub kid: i64,
    /// The RSA public key, serialized and deserialized as PEM format.
    #[serde(
        serialize_with = "serialize_rsa_public_key",
        deserialize_with = "deserialize_rsa_public_key"
    )]
    pub public_key: RsaPublicKey,
    /// The RSA private key, which is excluded from serialization and deserialization.
    #[serde(skip)]
    pub private_key: Option<RsaPrivateKey>,
    /// The expiry timestamp of the key pair in UNIX timestamp format.
    pub expiry: u64,
}

/// Serializes an `RsaPublicKey` to a PEM format string for storage or transmission.
fn serialize_rsa_public_key<S>(key: &RsaPublicKey, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let pem = key
        .to_public_key_pem(LineEnding::CRLF)
        .map_err(serde::ser::Error::custom)?;
    serializer.serialize_str(&pem)
}

/// Deserializes an `RsaPublicKey` from a PEM format string.
fn deserialize_rsa_public_key<'de, D>(deserializer: D) -> Result<RsaPublicKey, D::Error>
where
    D: Deserializer<'de>,
{
    let pem = String::deserialize(deserializer)?;
    RsaPublicKey::from_public_key_pem(&pem).map_err(serde::de::Error::custom)
}

impl KeyPair {
    /// Creates a new RSA `KeyPair` with the specified unique identifier (`kid`), key size, and expiry duration.
    ///
    /// This function generates a new RSA key pair of the given size and sets its expiry based on the provided duration.
    /// It encapsulates the generated key pair within a `KeyPair` struct along with a unique identifier and expiry timestamp.
    ///
    /// # Parameters
    ///
    /// * `kid` - A unique identifier for the key pair. This is typically a UUID.
    /// * `expiry_duration` - The duration in seconds from the current time after which the key pair is considered expired.
    ///
    /// # Returns
    ///
    /// Returns a `Result` which is:
    ///
    /// - `Ok(KeyPair)` - A `KeyPair` instance if the key pair was successfully generated.
    /// - `Err(CryptoError)` - An `CryptoError` if an error occurred during key pair generation.
    ///
    /// # Errors
    ///
    /// This function can return an error if:
    ///
    /// - The RSA key generation fails due to invalid parameters or internal errors.
    /// - There are issues with system time retrieval.
    pub fn new(kid: i64, expiry_duration: i64) -> Result<Self, CryptoError> {
        let key_size_str = dotenv::var("KEY_SIZE")?;
        let key_size = key_size_str.parse::<usize>().map_err(CryptoError::from)?;

        let mut rng = OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, key_size)?;
        let public_key = RsaPublicKey::from(&private_key);

        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs() as u64;

        let expiry = if expiry_duration < 0 {
            current_time
                .checked_sub(expiry_duration.abs() as u64)
                .unwrap_or(0)
        } else {
            current_time
                .checked_add(expiry_duration as u64)
                .unwrap_or(u64::MAX)
        };

        let private_key = Some(private_key);

        Ok(Self {
            kid,
            public_key,
            private_key,
            expiry,
        })
    }

    pub fn from_private_key(
        kid: i64,
        key: &Vec<u8>,
        expiry_duration: i64,
    ) -> Result<Self, CryptoError> {
        let private_key = RsaPrivateKey::from_pkcs1_der(&key)
            .expect("Failed to decode PKCS#1 DER bytes into RsaPrivateKey");
        let public_key = RsaPublicKey::from(&private_key);

        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs() as u64;

        let expiry = if expiry_duration < 0 {
            current_time
                .checked_sub(expiry_duration.abs() as u64)
                .unwrap_or(0)
        } else {
            current_time
                .checked_add(expiry_duration as u64)
                .unwrap_or(u64::MAX)
        };

        let private_key = Some(private_key);

        Ok(Self {
            kid,
            public_key,
            private_key,
            expiry,
        })
    }

    /// Checks whether the key pair has expired based on the current system time.
    ///
    /// # Returns
    ///
    /// `true` if the key pair has expired, `false` otherwise.
    pub fn is_expired(&self) -> bool {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs() as u64;
        self.expiry < current_time
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_pair_generation() {
        let kid = 1;
        let expiry_duration: i64 = 3600;

        let key_pair = KeyPair::new(kid, expiry_duration).unwrap();

        assert_eq!(key_pair.kid, kid);
        assert!(key_pair.private_key.is_some());
        // Check if the expiry is roughly in the future by at least the expiry duration minus a small delta
        let now_i64 = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs() as i64;

        let now_u64 = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs() as u64;

        assert!(key_pair.expiry > now_u64 && key_pair.expiry <= (now_i64 + expiry_duration) as u64);
    }

    #[test]
    fn key_pair_expiry() {
        let expiry_duration = 1; // 1 second
        let key_pair = KeyPair::new(1, expiry_duration).unwrap();

        // Sleep for 2 seconds to ensure the key expires
        std::thread::sleep(std::time::Duration::new(2, 0));
        assert!(key_pair.is_expired());
    }
}
