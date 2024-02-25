#[get("/")]
pub fn index() -> &'static str {
    "Howdy!"
}

#[post("/auth")]
pub fn auth() -> &'static str {
    "Auth"
}
