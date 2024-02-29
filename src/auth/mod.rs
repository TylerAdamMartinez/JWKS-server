use crate::crypto::error::HashError;
use bcrypt::{hash, DEFAULT_COST};
use serde::Deserialize;
use sqlx::{FromRow, SqlitePool};
use uuid::Uuid;

/// Represents credentials with a username and password.
#[derive(Debug, Deserialize)]
pub struct LoginDTO {
    pub username: String,
    pub password: String,
}

/// Represents a user with a unique identifier, username, and password hash.
#[derive(FromRow, Debug, Deserialize)]
pub struct User {
    /// The unique identifier of the user.
    pub user_id: Uuid,
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
    password: &str,
) -> Result<User, sqlx::Error> {
    let user_id = Uuid::new_v4();
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
        "INSERT INTO users (user_id, username, password_hash) VALUES (?, ?, ?)",
        user_id,
        username,
        password_hash
    )
    .execute(db_pool)
    .await?;

    Ok(User {
        user_id,
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

/// Finds a user by username in the database.
///
/// # Arguments
///
/// * `db_pool` - A connection pool to the SQLite database.
/// * `username` - The username of the user to find.
///
/// # Returns
///
/// Returns a `Result` which is `Ok` with `Some(User)` if the user is found,
/// `Ok` with `None` if the user is not found,
/// or an `Err` with an `sqlx::Error` on failure.
pub async fn find_user_by_username(
    db_pool: &SqlitePool,
    username: &str,
) -> Result<Option<User>, sqlx::Error> {
    let user = sqlx::query_as!(
        User,
        r#"SELECT user_id as "user_id: Uuid", username, password_hash FROM users WHERE username = ?"#,
        username
    )
    .fetch_optional(db_pool)
    .await?;

    Ok(user)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::SqlitePool;
    use tokio;

    async fn setup_db() -> Result<SqlitePool, sqlx::Error> {
        let pool = SqlitePool::connect(":memory:").await?;

        sqlx::query("CREATE TABLE users (user_id TEXT PRIMARY KEY NOT NULL, username TEXT NOT NULL, password_hash TEXT NOT NULL)")
            .execute(&pool)
            .await?;
        Ok(pool)
    }

    #[tokio::test]
    async fn test_create_user_and_find_user_by_username() {
        let db_pool = setup_db().await.expect("Failed to create the in-memory DB");

        let password = "password123";
        let hashed_password = hash_password(password).unwrap();

        let username = "testuser";
        create_user(&db_pool, username, &hashed_password)
            .await
            .expect("Failed to create user");

        let found_user = find_user_by_username(&db_pool, username)
            .await
            .expect("Failed to find user");

        assert!(found_user.is_some());
        let user = found_user.unwrap();
        assert_eq!(user.username, username);
    }
}
