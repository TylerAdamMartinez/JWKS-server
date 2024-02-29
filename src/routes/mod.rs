use crate::auth::LoginDTO;
use crate::auth::{create_user, find_user_by_username};
use crate::crypto::{CryptoError, Jwks, Jwt, KeyPair};
use rocket::serde::json::Json;
use sqlx::SqlitePool;
use uuid::Uuid;

/// Responds with a greeting message.
///
/// This is a simple endpoint to demonstrate a basic HTTP GET request.
#[get("/")]
pub fn index() -> &'static str {
    "Howdy!"
}

/// Provides the public keys in JWKS (JSON Web Key Set) format.
///
/// This endpoint serves public keys that are currently valid and have not expired,
/// allowing clients to verify the authenticity of JWTs issued by this server.
#[get("/.well-known/jwks.json")]
pub fn get_jwks() -> Json<Jwks> {
    let mut key_pairs = Vec::<KeyPair>::new();
    key_pairs.push(KeyPair::new(&Uuid::new_v4().to_string(), 1_000).unwrap());
    key_pairs.push(KeyPair::new(&Uuid::new_v4().to_string(), 10_000).unwrap());
    key_pairs.push(KeyPair::new(&Uuid::new_v4().to_string(), 15_000).unwrap());
    key_pairs.push(KeyPair::new(&Uuid::new_v4().to_string(), 30_000).unwrap());

    Json(Jwks::from_valid_pairs(key_pairs))
}

/// Authenticates a user and returns a JWT.
///
/// This endpoint issues JWTs for authenticated users. Clients can request an expired JWT
/// for testing purposes by setting the `expired` query parameter to `true`.
///
/// # Arguments
///
/// * `creds` - User credentials including a username and password.
/// * `expired` - An optional query parameter that dictates whether the issued JWT should be expired.
#[post("/auth?<expired>", data = "<creds>")]
pub async fn auth(
    db_pool: &rocket::State<SqlitePool>,
    creds: Json<LoginDTO>,
    expired: Option<bool>,
) -> Result<String, CryptoError> {
    let user_option = find_user_by_username(db_pool, &creds.username)
        .await
        .map_err(|_| CryptoError::DatabaseError)?;

    let user = match user_option {
        Some(user) => user,
        None => create_user(db_pool, &creds.username, &creds.password)
            .await
            .map_err(|_| CryptoError::DatabaseError)?,
    };

    let expiry_time = if expired.unwrap_or(false) {
        -36_000
    } else {
        36_000
    };

    Ok(Jwt::new(&user.user_id.to_string(), expiry_time)?)
}
