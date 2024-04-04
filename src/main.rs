#[macro_use]
extern crate rocket;

use crypto::KeyPair;
use dotenv;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use rocket::fairing::AdHoc;
use rsa::pkcs1::EncodeRsaPrivateKey;
use sqlx::SqlitePool;

mod auth;
mod crypto;
mod db;
mod routes;

/// Launches the Rocket web server with configured routes and database pool.
///
/// This function initializes the Rocket instance, sets up the database connection pool,
/// and mounts the application's routes. It reads the `DATABASE_URL` from the environment,
/// connects to the SQLite database, and injects the connection pool into Rocket's state
/// for use across the application.
///
/// # Panics
/// The function panics if:
/// - The `DATABASE_URL` environment variable is not set.
/// - The connection to the SQLite database fails.
///
/// # Returns
/// A configured `rocket::Rocket` instance ready for launching.
#[launch]
async fn rocket() -> _ {
    // Load environment variables from the .env file, if present.
    dotenv::dotenv().ok();

    let database_url = dotenv::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let db_pool = SqlitePool::connect(&database_url)
        .await
        .expect("Failed to create pool");

    sqlx::query!("DELETE FROM keys")
        .execute(&db_pool)
        .await
        .expect("err");

    sqlx::query!("DELETE FROM auth_logs")
        .execute(&db_pool)
        .await
        .expect("err");

    sqlx::query!("DELETE FROM users")
        .execute(&db_pool)
        .await
        .expect("err");

    sqlx::query!(
        "INSERT INTO users (id, username, email, password_hash) VALUES (1, 'test', 'test@test.com', 'password')"
    )
    .execute(&db_pool)
    .await
    .expect("err");

    let mut rng = StdRng::from_rng(rand::thread_rng()).expect("Failed to seed StdRng");
    let mut key_pairs = Vec::<KeyPair>::new();
    for i in 0..40 {
        let expiry: i64 = rng.gen_range(-360_000..=360_000);
        let key_pair = KeyPair::new(i, expiry).unwrap();
        key_pairs.push(key_pair.clone());
        let expiry_i32 = key_pair.expiry as i32;
        let der_bytes: Vec<u8> = key_pair
            .private_key
            .unwrap()
            .to_pkcs1_der()
            .unwrap()
            .as_bytes()
            .to_vec();

        sqlx::query!(
            "INSERT INTO keys (kid, key, exp) VALUES (?, ?, ?)",
            key_pair.kid,
            der_bytes,
            expiry_i32
        )
        .execute(&db_pool)
        .await
        .expect("err");
    }

    rocket::build()
        .attach(AdHoc::on_ignite("SQLite Database", |rocket| async {
            rocket.manage(db_pool)
        }))
        .manage(key_pairs)
        .mount(
            "/",
            routes![
                routes::index,
                routes::auth,
                routes::get_jwks,
                routes::register
            ],
        )
        .register("/auth", catchers![routes::not_found_to_method_not_allow])
        .register(
            "/.well-known/jwks.json",
            catchers![routes::not_found_to_method_not_allow],
        )
        .register(
            "/",
            catchers![routes::not_found, routes::method_not_allowed],
        )
}
