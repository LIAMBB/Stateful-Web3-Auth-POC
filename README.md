# Web3 Authentication Proof of Concept

This project demonstrates a proof of concept for Web3 authentication using Go. It implements a simple authentication server that supports both traditional JWT-based authentication and Web3 authentication using Ethereum addresses and signatures.

## Features

- Web3 authentication using Ethereum addresses and signatures
- JWT-based authentication with access and refresh tokens
- User registration and login
- SQLite database for user storage
- RSA key pair generation and management for JWT signing

## Getting Started

### Prerequisites

- Go 1.16 or higher
- SQLite

### Installation

1. Clone the repository:
   ```
   git clone https://github.com/liambb/web3-auth-poc.git
   cd web3-auth-poc
   ```

2. Install dependencies:
   ```
   go mod tidy
   ```

3. Run the server:
   ```
   go run main.go
   ```

The server will start on `localhost:8080`.

## API Endpoints

- `/web3/challenge`: Get a challenge for Web3 authentication
- `/web3/verify`: Verify the signed challenge and authenticate
- `/signup`: Register a new user
- `/test`: A protected endpoint that requires authentication

## Usage

For detailed information on how to use this authentication system and integrate it into your projects, please refer to the accompanying article:

[Web3 Authentication Proof of Concept](https://liambarter.me/projects/web3-auth-poc.html)

This article provides in-depth explanations of the implementation, security considerations, and potential use cases for this authentication system.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Go-Ethereum](https://github.com/ethereum/go-ethereum) for Ethereum-related cryptographic functions
- [GORM](https://gorm.io/) for database operations
- [JWT-Go](https://github.com/dgrijalva/jwt-go) for JWT operations

