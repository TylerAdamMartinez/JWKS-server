#[macro_use]
extern crate rocket;

use dotenv;
use rocket::fairing::AdHoc;
use sqlx::SqlitePool;

mod auth;
mod crypto;
mod routes;

#[launch]
async fn rocket() -> _ {
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
}
