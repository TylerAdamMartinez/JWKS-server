use rocket::http::Status;
use rocket::response::status;

#[doc(hidden)]
#[catch(404)]
pub fn not_found_to_method_not_allow() -> status::Custom<&'static str> {
    status::Custom(Status::MethodNotAllowed, "405: METHOD NOT ALLOWED")
}

/// Catcher for handling 404 Not Found errors.
///
/// This function is a generic catch-all for requests targeting non-existent endpoints.
/// It provides a simple response indicating that the requested resource could not be found.
///
/// # Returns
///
/// Returns a `status::NotFound` response with a "404: NOT FOUND" message,
/// signaling to the client that the requested endpoint does not exist.
#[catch(404)]
pub fn not_found() -> status::NotFound<&'static str> {
    status::NotFound("404: NOT FOUND")
}

/// Catcher for 405 Method Not Allowed errors.
///
/// This catcher is triggered when a request is made using an HTTP method that
/// is not supported by the targeted endpoint. It explicitly informs the client
/// that the method is not allowed for the requested resource, guiding them towards using
/// a correct method.
///
/// # Returns
///
/// Returns a `status::MethodNotAllowed` response with a "405: METHOD NOT ALLOWED" message.
#[catch(405)]
pub fn method_not_allowed() -> status::Custom<&'static str> {
    status::Custom(Status::MethodNotAllowed, "405: METHOD NOT ALLOWED")
}
