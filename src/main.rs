#[macro_use]
extern crate rocket;

use dotenv;
use rocket::fairing::AdHoc;
use sqlx::SqlitePool;

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

    let database_url = dotenv::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let db_pool = SqlitePool::connect(&database_url)
        .await
        .expect("Failed to create pool");

    rocket::build()
        .attach(AdHoc::on_ignite("SQLite Database", |rocket| async {
            rocket.manage(db_pool)
        }))
        .mount("/", routes![routes::index, routes::auth, routes::get_jwks])
        .register("/", catchers![routes::not_found])
}
