use crate::crypto::error::HashError;
use bcrypt::{hash, DEFAULT_COST};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, SqlitePool};

use rocket::http::Status;
use rocket::request::{FromRequest, Outcome, Request};

pub struct ClientIp(pub String);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for ClientIp {
    type Error = ();

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        match request.client_ip() {
            Some(ip) => Outcome::Success(ClientIp(ip.to_string())),
            None => Outcome::Error((Status::BadRequest, ())),
        }
    }
}

/// Represents credentials with a username and password.
#[derive(Debug, Deserialize, Default)]
pub struct LoginDTO {
    pub username: String,
    pub password: String,
}

/// Represents credentials with a username and email.
#[derive(Debug, Deserialize, Default)]
pub struct RegisterDTO {
    pub username: String,
    pub email: String,
}

/// Represents successful registeration response DTO.
#[derive(Debug, Serialize, Default)]
pub struct PasswordDTO {
    pub password: String,
}

impl PasswordDTO {
    pub fn new(password: &str) -> Self {
        Self {
            password: password.to_owned(),
        }
    }
}

/// Represents a user with a unique identifier, username, and password hash.
#[derive(FromRow, Debug, Deserialize)]
pub struct User {
    /// The unique identifier of the user.
    pub id: Option<i64>,
    /// The username of the user. Usernames are unique.
    pub username: String,
    /// The hash of the user's password for secure storage.
    pub password_hash: String,
}

/// Creates a new user in the database with the provided username and password hash.
///
/// # Arguments
///
/// * `db_pool` - A connection pool to the SQLite database.
/// * `username` - The username of the new user.
/// * `password` - The plain text password for the new user.
///
/// # Returns
///
/// Returns a `Result` which is `Ok` with the created `User` on success, or an `Err` with an `sqlx::Error` on failure.
pub async fn create_user(
    db_pool: &SqlitePool,
    username: &str,
    email: &str,
    password: &str,
) -> Result<User, sqlx::Error> {
    let username = username.to_string();
    let password_hash = hash_password(password).map_err(|_| {
        sqlx::Error::Database(Box::new(HashError::new(
            "Failed to hash password",
            Some(bcrypt::BcryptError::InvalidHash(
                "Failed to hash password".into(),
            )),
        )))
    })?;

    sqlx::query!(
        "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
        username,
        email,
        password_hash
    )
    .execute(db_pool)
    .await?;

    let user_record = sqlx::query!("SELECT id FROM users WHERE username = ?", username)
        .fetch_one(db_pool)
        .await?;

    Ok(User {
        id: user_record.id,
        username,
        password_hash,
    })
}

/// Hashes a password using bcrypt.
///
/// # Arguments
///
/// * `password` - The password to hash.
///
/// # Returns
///
/// Returns a `Result` with the hashed password on success or an error on failure.
fn hash_password(password: &str) -> Result<String, bcrypt::BcryptError> {
    hash(password, DEFAULT_COST)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::SqlitePool;
    use tokio;

    async fn setup_db() -> Result<SqlitePool, sqlx::Error> {
        let pool = SqlitePool::connect(":memory:").await?;

        sqlx::query(
            "
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                email TEXT UNIQUE,
                date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP      
            )
        ",
        )
        .execute(&pool)
        .await?;
        Ok(pool)
    }

    #[tokio::test]
    async fn test_create_user() {
        let db_pool = setup_db().await.expect("Failed to create the in-memory DB");

        let password = "password123";
        let email = "test@test.com";
        let hashed_password = hash_password(password).unwrap();

        let username = "testuser";
        create_user(&db_pool, email, username, &hashed_password)
            .await
            .expect("Failed to create user");

        let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users")
            .fetch_one(&db_pool)
            .await
            .expect("Failed to fetch user count");

        assert_eq!(count.0, 1, "A user should have been added.");
    }
}
