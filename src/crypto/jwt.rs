use super::{CryptoError, Jwk, KeyPair};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use rsa::pkcs8::{EncodePrivateKey, LineEnding};
use serde::{Deserialize, Serialize};

/// Represents custom claims for a JWT.
#[derive(Serialize, Deserialize)]
struct CustomClaims {
    /// The subject of the token (typically a user identifier).
    sub: String,
    /// The expiration time of the token as a timestamp.
    exp: u64,
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
    pub fn from(key_pair: &KeyPair) -> Result<String, CryptoError> {
        let claims = CustomClaims {
            sub: key_pair.kid.to_string(),
            exp: key_pair.expiry,
        };

        let pem_result = key_pair
            .clone()
            .private_key
            .unwrap()
            .to_pkcs8_pem(LineEnding::CRLF)
            .map_err(|_| CryptoError::KeyPairError);

        let pem = match pem_result {
            Ok(pem) => pem,
            Err(_) => return Err(CryptoError::KeyPairError(rsa::errors::Error::Internal)),
        };

        let jwk = Jwk::new(&key_pair.kid.to_string(), &key_pair.public_key);

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
        match Jwt::from(&KeyPair::new(1, 3600).unwrap()) {
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
