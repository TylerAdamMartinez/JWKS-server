use super::{CryptoError, Jwk, KeyPair};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use rsa::pkcs8::ToPrivateKey;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Serialize, Deserialize)]
struct CustomClaims {
    sub: String,
    exp: String,
}

#[derive(Serialize, Deserialize)]
pub struct Jwt {}

impl Jwt {
    pub fn new(sub: &str, exp: u64) -> Result<String, CryptoError> {
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
