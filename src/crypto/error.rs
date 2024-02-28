use dotenv;
use rocket::{
    http::Status,
    response::{self, Responder, Response},
    Request,
};

/// Represents errors that can occur within cryptographic operations.
#[derive(Debug)]
pub enum CryptoError {
    /// An error arising from RSA key pair generation or manipulation.
    ///
    /// This variant is used to encapsulate errors from the `rsa` crate,
    /// such as those occurring during the generation of a new RSA key pair
    /// or when manipulating existing keys.
    KeyPairError(rsa::errors::Error),

    /// An error related to system time operations.
    ///
    /// This variant is used when encountering issues with retrieving or
    /// manipulating system time, which may be needed for setting key
    /// expiration times or other time-sensitive cryptographic operations.
    SystemTimeError(std::time::SystemTimeError),

    /// Indicates a failure in JWT creation.
    ///
    /// This error is used when the JWT creation process fails, which might
    /// be due to issues with the payload, signing process, or other aspects
    /// of token generation.
    TokenCreationError,

    /// An error related to environment variable operations.
    ///
    /// This variant is used when encountering issues with retrieving
    /// environment variables, such as missing or malformed values that
    /// are expected to configure or drive cryptographic operations.
    EnvVarError(dotenv::Error),

    /// An error arising from parsing integer values.
    ///
    /// This variant is used when an error occurs while parsing string
    /// representations of integers into their respective numeric types.
    /// It is typically encountered when converting configuration values
    /// or parameters from text to numbers.
    ParseIntError(std::num::ParseIntError),
}

/// Allows conversion from `rsa::errors::Error` to `CryptoError`.
impl From<rsa::errors::Error> for CryptoError {
    fn from(err: rsa::errors::Error) -> CryptoError {
        CryptoError::KeyPairError(err)
    }
}

/// Allows conversion from `dotenv::Error` to `CryptoError`.
impl From<dotenv::Error> for CryptoError {
    fn from(err: dotenv::Error) -> CryptoError {
        CryptoError::EnvVarError(err)
    }
}

/// Allows conversion from `std::num::ParseIntError` to `CryptoError`.
impl From<std::num::ParseIntError> for CryptoError {
    fn from(err: std::num::ParseIntError) -> CryptoError {
        CryptoError::ParseIntError(err)
    }
}

/// Allows conversion from `jsonwebtoken::errors::Error` to `CryptoError`.
impl From<jsonwebtoken::errors::Error> for CryptoError {
    fn from(_err: jsonwebtoken::errors::Error) -> Self {
        CryptoError::TokenCreationError
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
            CryptoError::KeyPairError(_) => Response::build().status(Status::BadRequest).ok(),
            CryptoError::TokenCreationError
            | CryptoError::SystemTimeError(_)
            | CryptoError::ParseIntError(_)
            | CryptoError::EnvVarError(_) => {
                Response::build().status(Status::InternalServerError).ok()
            }
        }
    }
}
