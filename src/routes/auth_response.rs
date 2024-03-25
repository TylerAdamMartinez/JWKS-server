use crate::auth::LoginDTO;
use crate::auth::{create_user, find_user_by_username};
use crate::crypto::{CryptoError, Jwks, Jwt, KeyPair};
use crate::db::KeysTable;
use rocket::serde::json::Json;
use sqlx::SqlitePool;

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
/// * `creds` - User credentials including a username and password.
/// * `expired` - An optional query parameter that dictates whether the issued JWT should be expired.
#[post("/auth?<expired>", data = "<creds>")]
pub async fn auth(
    db_pool: &rocket::State<SqlitePool>,
    expired: Option<bool>,
    creds: Json<Option<LoginDTO>>,
) -> Result<String, CryptoError> {
    let user_creds = creds.into_inner().unwrap_or_default();
    let user_option = find_user_by_username(db_pool, &user_creds.username)
        .await
        .map_err(|_| CryptoError::DatabaseError)?;

    match user_option {
        Some(user) => user,
        None => create_user(db_pool, &user_creds.username, &user_creds.password)
            .await
            .map_err(|_| CryptoError::DatabaseError)?,
    };

    let find_expired = expired.unwrap_or(false);
    let private_keys: Vec<KeysTable> = sqlx::query_as!(KeysTable, "SELECT * FROM keys")
        .fetch_all(&**db_pool)
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
