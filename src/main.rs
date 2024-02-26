#[macro_use]
extern crate rocket;

mod crypto;
mod routes;

#[launch]
fn rocket() -> _ {
    rocket::build().mount(
        "/",
        routes![
            routes::index,
            routes::auth,
            routes::get_jwks,
            routes::create_key_pair
        ],
    )
}
