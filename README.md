# JWKS Server

## Overview

This project implements a simple web server that generates RSA key pairs and 
provides JWTs (JSON Web Tokens) through a RESTful API. It includes a JWKS 
(JSON Web Key Set) endpoint for serving public keys and an authentication 
endpoint for issuing JWTs. 

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

## Running the Server

1. Ensure Rust and Cargo are installed.
2. Navigate to the project root and run `cargo run` to start the server.
3. The server will be accessible on `http://localhost:8080`.

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

