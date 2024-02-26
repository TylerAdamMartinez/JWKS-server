use crate::crypto::{Jwk, Jwks, KeyPair, KeyPairParts};

use rocket::serde::json::Json;
use uuid::Uuid;

#[get("/")]
pub fn index() -> &'static str {
    "Howdy!"
}

#[get("/auth")]
pub fn get_jwks() -> Json<Jwks> {
    let mut key_pairs = Vec::<KeyPair>::new();
    key_pairs.push(KeyPair::new(&Uuid::new_v4().to_string(), 255, 1000));
    key_pairs.push(KeyPair::new(&Uuid::new_v4().to_string(), 1024, 10000));
    key_pairs.push(KeyPair::new(&Uuid::new_v4().to_string(), 255, 15000));
    key_pairs.push(KeyPair::new(&Uuid::new_v4().to_string(), 255, 30000));

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
pub fn auth(expired: bool) -> &'static str {
    if !expired {
        return "Auth";
    }

    "expired"
}
