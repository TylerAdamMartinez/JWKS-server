use super::Jwk;
use serde::Serialize;

/// Represents a JSON Web Key Set (JWKS).
///
/// JWKS is a set of keys containing the cryptographic information
/// required to verify tokens or signatures. This struct is typically
/// used to convey public keys in a JWKS endpoint.
#[derive(Serialize)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}
