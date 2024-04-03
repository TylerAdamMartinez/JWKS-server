pub mod auth_response;
pub use auth_response::{auth, get_jwks, register};

pub mod error_response;
pub use error_response::{method_not_allowed, not_found, not_found_to_method_not_allow};

pub mod index_response;
pub use index_response::index;
