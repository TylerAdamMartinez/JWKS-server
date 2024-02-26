use base64::engine::general_purpose;
use base64::Engine;
use rand::rngs::OsRng;
use rocket::{
    http::Status,
    response::{self, Responder, Response},
    Request,
};
#[warn(unused_imports)] // Trait used by base64::engine::general_purpose
use rsa::PublicKeyParts;
use rsa::{
    pkcs8::{FromPublicKey, ToPublicKey},
    RsaPrivateKey, RsaPublicKey,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::time::{SystemTime, UNIX_EPOCH};

/// Represents errors that can occur within cryptographic operations.
#[derive(Debug)]
pub enum CryptoError {
    /// An error that wraps an RSA key pair generation or manipulation error.
    KeyPairError(rsa::errors::Error),
    /// An error that wraps issues encountered with system time operations.
    SystemTimeError(std::time::SystemTimeError),
}

/// Allows conversion from `rsa::errors::Error` to `CryptoError`.
impl From<rsa::errors::Error> for CryptoError {
    fn from(err: rsa::errors::Error) -> CryptoError {
        CryptoError::KeyPairError(err)
    }
}

/// Enables conversion from `std::time::SystemTimeError` to `CryptoError`.
impl From<std::time::SystemTimeError> for CryptoError {
    fn from(err: std::time::SystemTimeError) -> CryptoError {
        CryptoError::SystemTimeError(err)
    }
}

/// Implementation of the `Responder` trait for `CryptoError`.
/// This allows `CryptoError` instances to be directly used in Rocket handler responses.
impl<'r> Responder<'r, 'static> for CryptoError {
    /// Converts a `CryptoError` into a Rocket response.
    ///
    /// # Returns
    ///
    /// A Rocket response indicating an error occurred.
    fn respond_to(self, _: &'r Request<'_>) -> response::Result<'static> {
        match self {
            CryptoError::KeyPairError(_) => {
                // Maps `KeyPairError` to a `BadRequest` (400) status code.
                Response::build().status(Status::BadRequest).ok()
            }
            CryptoError::SystemTimeError(_) => {
                // Maps `SystemTimeError` to an `InternalServerError` (500) status code.
                Response::build().status(Status::InternalServerError).ok()
            }
        }
    }
}

/// Represents a JSON Web Key Set (JWKS).
///
/// JWKS is a set of keys containing the cryptographic information
/// required to verify tokens or signatures. This struct is typically
/// used to convey public keys in a JWKS endpoint.
#[derive(Serialize)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

/// Represents a single JSON Web Key (JWK).
///
/// A JWK is a JSON object that represents a cryptographic key. The
/// members of the object represent properties of the key, including
/// its value and usage.
#[derive(Serialize)]
pub struct Jwk {
    /// The key type parameter defining the cryptographic algorithm family
    /// used with the key, such as RSA or EC.
    pub kty: String,
    /// The intended use of the public key. Commonly used values include
    /// `sig` (for signature) or `enc` (for encryption).
    pub use_: String,
    /// A unique identifier for the key. This can be used to match a specific key.
    pub kid: String,
    /// The RSA public key modulus for the RSA public key represented
    /// as a base64url-encoded string.
    pub n: String,
    /// The RSA public key exponent for the RSA public key represented
    /// as a base64url-encoded string.
    pub e: String,
}

impl Jwk {
    /// Creates a new `Jwk` instance for a given RSA public key.
    ///
    /// This method initializes a JSON Web Key (JWK) with the specified key
    /// identifier (`kid`) and RSA public key. The `kty` field is set to `"RSA"`
    /// to indicate the key type, and the `use_` field is set to `"sig"` to
    /// specify that the key is intended for signing operations. The modulus (`n`)
    /// and exponent (`e`) of the RSA public key are encoded using base64url
    /// without padding, in accordance with the JWK specification.
    ///
    /// # Parameters
    ///
    /// - `kid`: A unique identifier for the key. This identifier is used to
    ///   match a specific key and should be unique within the set of keys in a JWKS.
    /// - `public_key`: A reference to an `RsaPublicKey` that contains the public
    ///   key information to be included in the JWK.
    ///
    /// # Returns
    ///
    /// Returns a `Jwk` instance representing the provided RSA public key.
    ///
    /// # Examples
    ///
    /// ```
    /// use rsa::RsaPublicKey;
    /// use your_crate::Jwk;
    ///
    /// // Assume `public_key` is a valid `RsaPublicKey` instance
    /// let kid = "example_kid";
    /// let jwk = Jwk::new(kid, &public_key);
    ///
    /// assert_eq!(jwk.kid, kid);
    /// assert_eq!(jwk.kty, "RSA");
    /// ```
    pub fn new(kid: &str, public_key: &RsaPublicKey) -> Self {
        Self {
            kty: "RSA".to_string(),
            use_: "sig".to_string(),
            kid: kid.to_string(),
            n: general_purpose::URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be()),
            e: general_purpose::URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be()),
        }
    }
}

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
    use rand::rngs::OsRng;

    fn generate_test_rsa_public_key() -> RsaPublicKey {
        let mut rng = OsRng;
        let bits = 2048;
        let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
        private_key.to_public_key()
    }

    #[test]
    fn test_jwk_new_sets_correct_fields() {
        let test_kid = "test_kid";
        let test_public_key = generate_test_rsa_public_key();

        let jwk = Jwk::new(test_kid, &test_public_key);

        assert_eq!(jwk.kty, "RSA");
        assert_eq!(jwk.use_, "sig");
        assert_eq!(jwk.kid, test_kid);

        let n_encoded = general_purpose::URL_SAFE_NO_PAD.encode(test_public_key.n().to_bytes_be());
        let e_encoded = general_purpose::URL_SAFE_NO_PAD.encode(test_public_key.e().to_bytes_be());

        assert_eq!(jwk.n, n_encoded, "Modulus (n) is not correctly encoded.");
        assert_eq!(jwk.e, e_encoded, "Exponent (e) is not correctly encoded.");
    }

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
