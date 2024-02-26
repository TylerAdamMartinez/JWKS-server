use super::{CryptoError, Jwk, KeyPair};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use rsa::pkcs8::ToPrivateKey;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Represents custom claims for a JWT.
#[derive(Serialize, Deserialize)]
struct CustomClaims {
    /// The subject of the token (typically a user identifier).
    sub: String,
    /// The expiration time of the token as a timestamp.
    exp: String,
}

/// A struct for handling JSON Web Tokens (JWTs).
#[derive(Serialize, Deserialize)]
pub struct Jwt {}

impl Jwt {
    /// Creates a new JWT for a specified subject with an expiration.
    ///
    /// # Arguments
    ///
    /// * `sub` - A string slice that holds the subject of the token.
    /// * `exp` - The expiration time of the token in seconds since the Epoch.
    ///
    /// # Returns
    ///
    /// A `Result` which is either a string representing the JWT on success,
    /// or a `CryptoError` on failure.
    ///
    /// # Examples
    ///
    /// ```
    /// let jwt = Jwt::new("user123", 3600)?;
    /// ```
    pub fn new(sub: &str, exp: i64) -> Result<String, CryptoError> {
        let key_pair = KeyPair::new(&Uuid::new_v4().to_string(), 2048, exp)?;

        let claims = CustomClaims {
            sub: sub.to_string(),
            exp: key_pair.expiry.to_string(),
        };

        let pem_result = key_pair
            .private_key
            .unwrap()
            .to_pkcs8_pem()
            .map_err(|_| CryptoError::KeyPairError);

        let pem = match pem_result {
            Ok(pem) => pem,
            Err(_) => return Err(CryptoError::KeyPairError(rsa::errors::Error::Internal)),
        };

        let jwk = Jwk::new(&key_pair.kid, &key_pair.public_key);

        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(jwk.kid.clone());

        let encoding_key = EncodingKey::from_rsa_pem(&pem.as_bytes()).map_err(CryptoError::from)?;

        encode(&header, &claims, &encoding_key).map_err(|_| CryptoError::TokenCreationError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jwt_creation_success() {
        let subject = "testuser";
        let expiration = 3600;

        match Jwt::new(subject, expiration) {
            Ok(jwt) => {
                assert!(
                    !jwt.is_empty(),
                    "JWT should not be empty on successful creation."
                );
            }
            Err(e) => panic!(
                "Expected JWT to be created successfully, but got an error: {:?}",
                e
            ),
        }
    }
}
