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
    /// Creates a new `KeyPair` with the specified unique identifier (`kid`), key size, and expiry duration.
    ///
    /// # Parameters
    ///
    /// * `kid` - A unique identifier for the key pair.
    /// * `key_size` - The size of the RSA key in bits.
    /// * `expiry_duration` - The duration from the current time after which the key pair expires, in seconds.
    ///
    /// # Returns
    ///
    /// A new `KeyPair` instance.
    pub fn new(kid: &str, key_size: usize, expiry_duration: u64) -> Self {
        let mut rng = OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, key_size).expect("Failed to generate a key");
        let public_key = RsaPublicKey::from(&private_key);

        let private_key = Some(private_key);
        let expiry = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs()
            + expiry_duration;

        KeyPair {
            kid: kid.to_owned(),
            public_key,
            private_key,
            expiry,
        }
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
