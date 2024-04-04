use crate::auth::{create_user, ClientIp, PasswordDTO, RateLimited, RegisterDTO};
use crate::crypto::{CryptoError, Jwks, Jwt, KeyPair};
use crate::db::KeysTable;
use rocket::http::Status;
use rocket::response::status;
use rocket::serde::json::Json;
use sqlx::SqlitePool;
use uuid::Uuid;

/// Provides the public keys in JWKS (JSON Web Key Set) format.
///
/// This endpoint serves public keys that are currently valid and have not expired,
/// allowing clients to verify the authenticity of JWTs issued by this server.
#[get("/.well-known/jwks.json")]
pub async fn get_jwks(db_pool: &rocket::State<SqlitePool>) -> Json<Jwks> {
    let private_keys: Vec<KeysTable> = sqlx::query_as!(KeysTable, "SELECT * FROM keys")
        .fetch_all(&**db_pool)
        .await
        .expect("");

    let key_pairs: Vec<KeyPair> = private_keys
        .iter()
        .map(|pk| KeyPair::from_private_key(pk.kid, &pk.key, pk.exp).unwrap())
        .filter(|kp| !kp.is_expired())
        .collect();
    Json(Jwks::from_valid_pairs(key_pairs))
}

/// Authenticates a user and returns a JWT.
///
/// This endpoint issues JWTs for authenticated users. Clients can request an expired JWT
/// for testing purposes by setting the `expired` query parameter to `true`.
///
/// # Arguments
///
/// * `expired` - An optional query parameter that dictates whether the issued JWT should be expired.
#[post("/auth?<expired>")]
pub async fn auth(
    db_pool: &rocket::State<SqlitePool>,
    request_ip: ClientIp,
    _rate_limited: RateLimited,
    expired: Option<bool>,
) -> Result<String, CryptoError> {
    let find_expired = expired.unwrap_or(false);
    let private_keys: Vec<KeysTable> = sqlx::query_as!(KeysTable, "SELECT * FROM keys")
        .fetch_all(&**db_pool)
        .await
        .expect("Unable to get keys from keys table");

    let request_ip = request_ip.0;
    let user_id = 1;

    sqlx::query!(
        "INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)",
        request_ip,
        user_id
    )
    .execute(&**db_pool)
    .await
    .expect("");

    let key_pairs: Vec<KeyPair> = private_keys
        .iter()
        .map(|pk| KeyPair::from_private_key(pk.kid, &pk.key, pk.exp).unwrap())
        .collect();

    let key_pair = key_pairs
        .iter()
        .find(|kp| find_expired == kp.is_expired())
        .ok_or(CryptoError::TokenCreationError)?;

    Ok(Jwt::from(&key_pair)?)
}

#[post("/register", data = "<creds>")]
pub async fn register(
    db_pool: &rocket::State<SqlitePool>,
    creds: Json<RegisterDTO>,
) -> Result<status::Custom<Json<PasswordDTO>>, Json<String>> {
    let new_generated_password = Uuid::new_v4().to_string();

    create_user(
        db_pool,
        &creds.username,
        &creds.email,
        &new_generated_password,
    )
    .await
    .expect("failed to create new user");

    Ok(status::Custom(
        Status::Created,
        Json(PasswordDTO::new(&new_generated_password)),
    ))
}
