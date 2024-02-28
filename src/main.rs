#[macro_use]
extern crate rocket;

use dotenv;

mod crypto;
mod routes;

#[launch]
fn rocket() -> _ {
    dotenv::dotenv().ok();
    rocket::build().mount("/", routes![routes::index, routes::auth, routes::get_jwks])
}
