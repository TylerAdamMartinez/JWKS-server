use crate::crypto::{CryptoError, Jwk, Jwks, Jwt, KeyPair};
use std::{
    time::{SystemTime, UNIX_EPOCH},
    u64,
};

use rocket::serde::json::Json;
use uuid::Uuid;

#[get("/")]
pub fn index() -> &'static str {
    "Howdy!"
}

#[get("/create-key-pair?<key_size>&<expiry_duration>")]
pub fn create_key_pair(
    key_size: usize,
    expiry_duration: u64,
) -> Result<Json<KeyPair>, CryptoError> {
    let new_key_pair = KeyPair::new(&Uuid::new_v4().to_string(), key_size, expiry_duration)?;
    Ok(Json(new_key_pair))
}

#[get("/.well-known/jwks.json")]
pub fn get_jwks() -> Json<Jwks> {
    let mut key_pairs = Vec::<KeyPair>::new();
    key_pairs.push(KeyPair::new(&Uuid::new_v4().to_string(), 255, 1_000).unwrap());
    key_pairs.push(KeyPair::new(&Uuid::new_v4().to_string(), 1024, 10_000).unwrap());
    key_pairs.push(KeyPair::new(&Uuid::new_v4().to_string(), 255, 15_000).unwrap());
    key_pairs.push(KeyPair::new(&Uuid::new_v4().to_string(), 255, 30_000).unwrap());

    Json(Jwks {
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
    })
}

#[post("/auth?<expired>")]
pub fn auth(expired: bool) -> Result<String, CryptoError> {
    let expiry_time = if expired {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as u64
            - 3600
    } else {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as u64
            + 3600
    };

    Ok(Jwt::new(&Uuid::new_v4().to_string(), expiry_time)?)
}
