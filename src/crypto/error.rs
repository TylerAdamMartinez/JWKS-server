use rocket::{
    http::Status,
    response::{self, Responder, Response},
    Request,
};

/// Represents errors that can occur within cryptographic operations.
#[derive(Debug)]
pub enum CryptoError {
    /// An error that wraps an RSA key pair generation or manipulation error.
    KeyPairError(rsa::errors::Error),
    /// An error that wraps issues encountered with system time operations.
    SystemTimeError(std::time::SystemTimeError),
}

/// Allows conversion from `rsa::errors::Error` to `CryptoError`.
impl From<rsa::errors::Error> for CryptoError {
    fn from(err: rsa::errors::Error) -> CryptoError {
        CryptoError::KeyPairError(err)
    }
}

/// Enables conversion from `std::time::SystemTimeError` to `CryptoError`.
impl From<std::time::SystemTimeError> for CryptoError {
    fn from(err: std::time::SystemTimeError) -> CryptoError {
        CryptoError::SystemTimeError(err)
    }
}

/// Implementation of the `Responder` trait for `CryptoError`.
/// This allows `CryptoError` instances to be directly used in Rocket handler responses.
impl<'r> Responder<'r, 'static> for CryptoError {
    /// Converts a `CryptoError` into a Rocket response.
    ///
    /// # Returns
    ///
    /// A Rocket response indicating an error occurred.
    fn respond_to(self, _: &'r Request<'_>) -> response::Result<'static> {
        match self {
            CryptoError::KeyPairError(_) => {
                // Maps `KeyPairError` to a `BadRequest` (400) status code.
                Response::build().status(Status::BadRequest).ok()
            }
            CryptoError::SystemTimeError(_) => {
                // Maps `SystemTimeError` to an `InternalServerError` (500) status code.
                Response::build().status(Status::InternalServerError).ok()
            }
        }
    }
}
