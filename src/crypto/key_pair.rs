use crate::crypto::error::CryptoError;
use rand::rngs::OsRng;
use rsa::{
    pkcs8::{FromPublicKey, ToPublicKey},
    RsaPrivateKey, RsaPublicKey,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::time::{SystemTime, UNIX_EPOCH};

/// Represents a RSA key pair with a unique identifier and expiry timestamp.
#[derive(Serialize, Deserialize)]
pub struct KeyPair {
    /// A unique identifier for the key pair.
    pub kid: String,
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
    let pem = key.to_public_key_pem().map_err(serde::ser::Error::custom)?;
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
    /// * `key_size` - The size of the RSA key in bits. Common sizes are 2048 or 4096 bits.
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
    pub fn new(kid: &str, key_size: usize, expiry_duration: u64) -> Result<Self, CryptoError> {
        let mut rng = OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, key_size)?;
        let public_key = RsaPublicKey::from(&private_key);

        let private_key = Some(private_key);
        let expiry = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() + expiry_duration;

        Ok(Self {
            kid: kid.to_owned(),
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
            .as_secs();

        self.expiry <= current_time
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_pair_generation() {
        let kid = "test_key";
        let key_size = 2048;
        let expiry_duration = 3600; // 1 hour
        let key_pair = KeyPair::new(kid, key_size, expiry_duration).unwrap();

        assert_eq!(key_pair.kid, kid);
        assert!(key_pair.private_key.is_some());
        // Check if the expiry is roughly in the future by at least the expiry duration minus a small delta
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();
        assert!(key_pair.expiry > now && key_pair.expiry <= now + expiry_duration);
    }

    #[test]
    fn key_pair_expiry() {
        let kid = "expired_key";
        let key_size = 2048;
        let expiry_duration = 1; // 1 second
        let key_pair = KeyPair::new(kid, key_size, expiry_duration).unwrap();

        // Sleep for 2 seconds to ensure the key expires
        std::thread::sleep(std::time::Duration::new(2, 0));
        assert!(key_pair.is_expired());
    }
}
