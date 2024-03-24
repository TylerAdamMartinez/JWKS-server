/// Responds with a greeting message.
///
/// This is a simple endpoint to demonstrate a basic HTTP GET request.
#[get("/")]
pub fn index() -> &'static str {
    "Howdy!"
}
