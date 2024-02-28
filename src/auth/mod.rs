use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Cred {
    pub username: String,
    pub password: String,
}
