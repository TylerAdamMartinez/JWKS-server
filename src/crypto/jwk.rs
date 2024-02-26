use base64::engine::general_purpose;
use base64::Engine;
#[warn(unused_imports)] // Trait used by base64::engine::general_purpose
use rsa::PublicKeyParts;
use rsa::RsaPublicKey;
use serde::Serialize;

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

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use rsa::RsaPrivateKey;

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
}
