#[macro_use]
extern crate rocket;

use crypto::KeyPair;
use dotenv;
use rocket::fairing::AdHoc;
use sqlx::SqlitePool;
use uuid::Uuid;

mod auth;
mod crypto;
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

    let mut key_pairs = Vec::<KeyPair>::new();
    for _ in 0..40 {
        key_pairs.push(KeyPair::new(&Uuid::new_v4().to_string(), rand::random::<i64>()).unwrap());
    }

    let database_url = dotenv::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let db_pool = SqlitePool::connect(&database_url)
        .await
        .expect("Failed to create pool");

    rocket::build()
        .attach(AdHoc::on_ignite("SQLite Database", |rocket| async {
            rocket.manage(db_pool)
        }))
        .manage(key_pairs)
        .mount("/", routes![routes::index, routes::auth, routes::get_jwks])
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
