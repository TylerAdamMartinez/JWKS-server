# JWKS Server

**PLEASE CHECKOUT THE DOC SITE [HERE](https://tyleradammartinez.github.io/JWKS-server/jwks_server/index.html)!!**

## Overview

This project implements a simple web server that generates RSA key pairs and 
provides JWTs (JSON Web Tokens) through a RESTful API. It includes a JWKS 
(JSON Web Key Set) endpoint for serving public keys and an authentication 
endpoint for issuing JWTs. 

## Setup and Running Instructions
Before running the JWKS Server, ensure you have completed the following setup steps:

### Prerequisites
Install Rust and Cargo: Make sure Rust and Cargo are installed on your system. You can download them from [rust-lang.org](https://www.rust-lang.org).  

Install SQLx CLI: The SQLx CLI tool is used for handling database migrations. Install it by running:  
```bash
cargo install sqlx-cli --no-default-features --features native-tls,sqlite
```
This command installs the SQLx CLI with SQLite support.  

### Database Setup
1. **Environment Variables**: Copy the .env.example file to .env to use as your environment configuration.
```bash
cp .env.example .env
```
Make sure to adjust any variables in .env as needed, particularly DATABASE_URL to match your database setup.  

2. **Create SQLite Database**: Based on your DATABASE_URL from the .env file, ensure the database exists. For SQLite, the database file specified in DATABASE_URL will be automatically created by SQLx if it doesn't exist, but you can also manually create it if necessary.

3. **Run Migrations**: With the SQLx CLI tool installed and your environment configured, run the following command to apply database migrations:
```bash
sqlx migrate run
```
This command sets up the necessary database schema for the JWKS Server.  
### Running the Server
After setting up the environment and database, start the server by navigating to the project root and running:  
```bash
cargo run
```
The server will start and be accessible on http://localhost:8080, ready to handle requests to its endpoints.  

## Requirements

- **Key Generation**
  - Implement RSA key pair generation.
  - Associate a Key ID (kid) and expiry timestamp with each key.

- **Web Server**
  - Serve HTTP on port 8080.
  - Implement a RESTful JWKS endpoint to serve the public keys in JWKS format, 
  only including keys that have not expired.
  - Implement an `/auth` endpoint to return an unexpired, signed JWT on a POST 
  request. If the "expired" query parameter is present, issue a JWT signed with an expired key pair.

- **Documentation**
  - Organize and comment the code where needed.
  - Adhere to the linting standards of the used language/framework.

- **Tests**
  - Include a test suite with coverage over 80%.

- **Blackbox Testing**
  - Ensure compatibility with an external test client for POST requests to `/auth`.

## Project Structure
```
JWKS-server/
├── Cargo.lock
├── Cargo.toml
├── Rocket.toml
├── .gitignore
├── .env.example
├── .env
├── src/
│ ├── crypto/
│ │ ├── error.rs
│ │ ├── jwk.rs
│ │ ├── jwks.rs
│ │ ├── jwt.rs
│ │ ├── key_pair.rs
│ │ └── mod.rs
│ ├── routes/
│ │ └── mod.rs
│ └── main.rs
└── target/
```

## Endpoints

The server provides the following endpoints:

### GET `/`

A simple endpoint that returns a greeting message, demonstrating a basic HTTP GET request.

Response:  
```bash
Howdy!
```

### GET `/.well-known/jwks.json`

Serves the public keys used by the server in JWKS (JSON Web Key Set) format. 
This endpoint ensures that only keys that have not expired are included, enabling 
clients to verify the authenticity of JWTs issued by this server.

Response:  
```json
{
  "keys": [
    // Public keys in JWKS format
  ]
}
```

### POST `/auth?expired=[true|false]`

Issues a JWT (JSON Web Token) for authenticated users. 
This endpoint allows clients to request an expired JWT for 
testing purposes by setting the expired query parameter to true.

request (Content-Type: application/json):  
```json
{
  "username": "user",
  "password": "pass"
}
```

Response:  
A JWT in text format.

## Testing

- Run `cargo test` to execute the test suite.
- Ensure blackbox testing compatibility with the provided external test client.

