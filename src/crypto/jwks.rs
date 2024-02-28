use super::{Jwk, KeyPair};
use serde::Serialize;

/// Represents a JSON Web Key Set (JWKS).
///
/// JWKS is a set of keys containing the cryptographic information
/// required to verify tokens or signatures. This struct is typically
/// used to convey public keys in a JWKS endpoint.
#[derive(Serialize)]
pub struct Jwks {
    /// A collection of `Jwk` objects, each representing a public key.
    pub keys: Vec<Jwk>,
}

impl Jwks {
    /// Filters and returns a `Jwks` instance containing only the non-expired keys
    /// from the given `key_pairs`.
    ///
    /// This method is used to prepare a JWKS response with valid keys, omitting
    /// any that have expired.
    ///
    /// # Arguments
    ///
    /// * `key_pairs` - A vector of `KeyPair` instances.
    ///
    /// # Returns
    ///
    /// Returns a `Jwks` instance containing only valid, non-expired `Jwk` keys.
    pub fn from_valid_pairs(key_pairs: Vec<KeyPair>) -> Self {
        Self {
            keys: key_pairs
                .into_iter()
                .filter_map(|jwt_key| {
                    if !jwt_key.is_expired() {
                        Some(Jwk::new(&jwt_key.kid, &jwt_key.public_key))
                    } else {
                        None
                    }
                })
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mock_key_pair(kid: &str, is_expired: bool) -> KeyPair {
        let expiration = if is_expired { -72_000 } else { 72_000 };

        KeyPair::new(&kid.to_string(), expiration).unwrap()
    }

    #[test]
    fn test_from_valid_pairs() {
        let key_pairs = vec![
            mock_key_pair("valid1", false),
            mock_key_pair("expired1", true),
            mock_key_pair("valid2", false),
            mock_key_pair("expired2", true),
            mock_key_pair("valid3", false),
            mock_key_pair("valid4", false),
            mock_key_pair("expired3", true),
            mock_key_pair("valid5", false),
        ];

        let jwks = Jwks::from_valid_pairs(key_pairs);

        assert_eq!(
            jwks.keys.len(),
            5,
            "Jwks should only include non-expired keys."
        );
    }
}
