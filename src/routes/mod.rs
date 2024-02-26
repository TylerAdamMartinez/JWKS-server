use crate::crypto::{CryptoError, Jwks, Jwt, KeyPair};
use rocket::serde::json::Json;
use serde::Deserialize;
use uuid::Uuid;

#[get("/")]
pub fn index() -> &'static str {
    "Howdy!"
}

#[get("/create-key-pair?<key_size>&<expiry_duration>")]
pub fn create_key_pair(
    key_size: usize,
    expiry_duration: i64,
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

    Json(Jwks::from_valid_pairs(key_pairs))
}

#[derive(Debug, Deserialize)]
pub struct Cred {
    pub username: String,
    pub password: String,
}

#[post("/auth?<expired>", data = "<creds>")]
pub fn auth(creds: Json<Cred>, expired: Option<bool>) -> Result<String, CryptoError> {
    println!("{:#?}", creds);

    let expiry_time = if expired.unwrap_or(false) {
        -36_000
    } else {
        36_000
    };

    Ok(Jwt::new(&Uuid::new_v4().to_string(), expiry_time)?)
}
