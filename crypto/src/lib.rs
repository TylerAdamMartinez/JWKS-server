use rand::rngs::OsRng;
use rsa::{
    pkcs8::{FromPublicKey, ToPublicKey},
    RsaPrivateKey, RsaPublicKey,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Serialize, Deserialize)]
pub struct KeyPair {
    pub kid: String,
    #[serde(
        serialize_with = "serialize_rsa_public_key",
        deserialize_with = "deserialize_rsa_public_key"
    )]
    pub public_key: RsaPublicKey,
    #[serde(skip)]
    pub private_key: Option<RsaPrivateKey>,
    pub expiry: u64,
}

fn serialize_rsa_public_key<S>(key: &RsaPublicKey, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let pem = key.to_public_key_pem().map_err(serde::ser::Error::custom)?;
    serializer.serialize_str(&pem)
}

fn deserialize_rsa_public_key<'de, D>(deserializer: D) -> Result<RsaPublicKey, D::Error>
where
    D: Deserializer<'de>,
{
    let pem = String::deserialize(deserializer)?;
    RsaPublicKey::from_public_key_pem(&pem).map_err(serde::de::Error::custom)
}

impl KeyPair {
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

    pub fn is_expired(&self) -> bool {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();

        self.expiry <= current_time
    }
}

/*
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
*/
