package main

// Package main Auth API
//
// This is a sample authentication server with Web3 auth support.
//
//     Schemes: http
//     Host: localhost:8080
//     BasePath: /
//     Version: 1.0.0
//
//     Consumes:
//     - application/json
//
//     Produces:
//     - application/json
//
// swagger:meta
import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/go-openapi/runtime/middleware"
	"github.com/google/uuid"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var db *gorm.DB
var privateKey *rsa.PrivateKey
var publicKey *rsa.PublicKey

const (
	privateKeyFile = "private_key.pem"
	publicKeyFile  = "public_key.pem"
)

// User represents the user model in the database
// swagger:model
type User struct {
	gorm.Model
	Username   string `gorm:"unique;not null" json:"username"`
	EthAddress string `gorm:"unique" json:"eth_address"`
	PublicKey  string `gorm:"unique" json:"public_key"`
}

// RefreshToken represents the refresh token model in the database
// swagger:model
type RefreshToken struct {
	gorm.Model
	Token  string `gorm:"primaryKey"`
	UserID uint
	User   User
	Expiry time.Time
	Used   bool `gorm:"default:false"`
}

// Web3Token represents the Web3 token model in the database
// swagger:model
type Web3Token struct {
	gorm.Model
	Token  string `gorm:"primaryKey"`
	UserID uint
	User   User
	Expiry time.Time
	Used   bool `gorm:"default:false"`
}

// Claims represents the JWT claims structure
// swagger:model
type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

// TokenPair represents a pair of access and refresh tokens
// swagger:model
type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// Web3Challenge represents a challenge for Web3 authentication
// swagger:model
type Web3Challenge struct {
	Challenge string `json:"challenge"`
}

// Web3SignedChallenge represents a signed challenge for Web3 authentication
// swagger:model
type Web3SignedChallenge struct {
	Address   string `json:"address"`
	PublicKey string `json:"public_key"`
	Challenge string `json:"challenge"`
	Signature string `json:"signature"`
}

// SignupChallenge represents a challenge for signup
type SignupChallenge struct {
	Address   string
	Challenge string
}

// pendingChallenges stores the pending signup challenges
var pendingChallenges = make(map[string]SignupChallenge)

// generateChallenge creates a random challenge string for authentication
func generateChallenge() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// main is the entry point of the application
func main() {
	var err error
	db, err = gorm.Open(sqlite.Open("auth.db"), &gorm.Config{})
	if err != nil {
		log.Fatal(err)
	}

	// Migrate the database schema
	db.AutoMigrate(&User{}, &RefreshToken{}, &Web3Token{})

	// Load or generate RSA keys for JWT signing
	err = loadOrGenerateRSAKeys()
	if err != nil {
		log.Fatalf("Failed to load or generate RSA keys: %v", err)
	}

	// Set up HTTP routes
	http.HandleFunc("/web3/challenge", web3Challenge)
	http.HandleFunc("/web3/verify", web3Verify)
	http.HandleFunc("/signup", signup)
	http.HandleFunc("/test", tokenMiddleware(testEndpoint))

	// Set up Swagger UI
	opts := middleware.SwaggerUIOpts{SpecURL: "/swagger.json"}
	sh := middleware.SwaggerUI(opts, nil)
	http.Handle("/docs", sh)
	http.Handle("/swagger.json", http.FileServer(http.Dir("./")))

	// Start the HTTP server
	log.Println("Server starting on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

// web3Challenge generates and returns a challenge for Web3 authentication
func web3Challenge(w http.ResponseWriter, r *http.Request) {
	challenge := make([]byte, 32)
	_, err := rand.Read(challenge)
	if err != nil {
		http.Error(w, "Error generating challenge", http.StatusInternalServerError)
		return
	}

	response := Web3Challenge{
		Challenge: hex.EncodeToString(challenge),
	}

	json.NewEncoder(w).Encode(response)
}

// web3Verify verifies the Web3 authentication challenge and creates or updates the user
func web3Verify(w http.ResponseWriter, r *http.Request) {
	var signedChallenge Web3SignedChallenge
	err := json.NewDecoder(r.Body).Decode(&signedChallenge)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Verify the signature
	address := common.HexToAddress(signedChallenge.Address)
	pubKey, err := crypto.DecompressPubkey(common.FromHex(signedChallenge.PublicKey))
	if err != nil {
		http.Error(w, "Invalid public key", http.StatusBadRequest)
		return
	}

	challengeBytes, err := hex.DecodeString(signedChallenge.Challenge)
	if err != nil {
		http.Error(w, "Invalid challenge format", http.StatusBadRequest)
		return
	}

	signatureBytes := common.FromHex(signedChallenge.Signature)

	// Add prefix to the message. This is equivalent to what eth_sign does.
	prefixedChallenge := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(challengeBytes), challengeBytes)

	// Hash the prefixed message
	hash := crypto.Keccak256Hash([]byte(prefixedChallenge))

	// Verify the signature
	if !crypto.VerifySignature(crypto.FromECDSAPub(pubKey), hash.Bytes(), signatureBytes[:len(signatureBytes)-1]) {
		http.Error(w, "Signature verification failed", http.StatusUnauthorized)
		return
	}

	// Check if the user exists, if not, create a new user
	var user User
	result := db.Where("eth_address = ?", address.Hex()).First(&user)
	if result.Error != nil {
		// User doesn't exist, create a new one
		user = User{
			Username:   address.Hex(), // Use the Ethereum address as the username
			EthAddress: address.Hex(),
			PublicKey:  signedChallenge.PublicKey,
		}
		result = db.Create(&user)
		if result.Error != nil {
			http.Error(w, "Error creating user", http.StatusInternalServerError)
			return
		}
	} else {
		// User exists, update the public key if it's different
		if user.PublicKey != signedChallenge.PublicKey {
			user.PublicKey = signedChallenge.PublicKey
			db.Save(&user)
		}
	}

	// Create token pair
	tokenPair, err := createTokenPair(user.Username, user.ID)
	if err != nil {
		http.Error(w, "Error creating tokens", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(tokenPair)
}

// signup handles the user signup process
func signup(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Address   string `json:"address" binding:"required"`
		Username  string `json:"username" binding:"required"`
		Signature string `json:"signature"`
	}

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Check if this is the initial request or the challenge response
	if input.Signature == "" {
		// Generate and store a new challenge
		challenge := generateChallenge()
		pendingChallenges[input.Address] = SignupChallenge{
			Address:   input.Address,
			Challenge: challenge,
		}

		json.NewEncoder(w).Encode(map[string]string{"challenge": challenge})
		return
	}

	// Verify the challenge and signature
	challenge, exists := pendingChallenges[input.Address]
	if !exists {
		http.Error(w, "No pending challenge found", http.StatusBadRequest)
		return
	}

	// Verify the signature
	message := []byte(challenge.Challenge)
	publicKeyBytes, err := hex.DecodeString(input.Address[2:]) // Remove "0x" prefix
	if err != nil {
		http.Error(w, "Invalid address format", http.StatusBadRequest)
		return
	}

	publicKey, err := crypto.UnmarshalPubkey(publicKeyBytes)
	if err != nil {
		http.Error(w, "Invalid public key", http.StatusBadRequest)
		return
	}

	signatureBytes, err := hex.DecodeString(input.Signature[2:]) // Remove "0x" prefix
	if err != nil {
		http.Error(w, "Invalid signature format", http.StatusBadRequest)
		return
	}

	if !crypto.VerifySignature(crypto.FromECDSAPub(publicKey), crypto.Keccak256(message), signatureBytes[:64]) {
		http.Error(w, "Invalid signature", http.StatusUnauthorized)
		return
	}

	// If signature is valid, proceed with user creation
	user := User{
		Username:   input.Username,
		EthAddress: input.Address,
		PublicKey:  hex.EncodeToString(crypto.FromECDSAPub(publicKey)),
	}

	if err := db.Create(&user).Error; err != nil {
		http.Error(w, "Failed to create user", http.StatusInternalServerError)
		return
	}

	// Remove the challenge from pending challenges
	delete(pendingChallenges, input.Address)

	json.NewEncoder(w).Encode(map[string]string{"message": "User created successfully"})
}

// loadOrGenerateRSAKeys loads existing RSA keys or generates new ones if they don't exist
func loadOrGenerateRSAKeys() error {
	// Check if private key file exists
	if _, err := os.Stat(privateKeyFile); os.IsNotExist(err) {
		// Generate new RSA key pair
		log.Println("Generating new RSA key pair...")
		err := generateRSAKeys()
		if err != nil {
			return fmt.Errorf("failed to generate RSA keys: %v", err)
		}
	}

	// Load private key
	privateKeyBytes, err := os.ReadFile(privateKeyFile)
	if err != nil {
		return fmt.Errorf("failed to read private key: %v", err)
	}
	privateKeyPEM, _ := pem.Decode(privateKeyBytes)
	privateKey, err = x509.ParsePKCS1PrivateKey(privateKeyPEM.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse private key: %v", err)
	}

	// Load public key
	publicKeyBytes, err := os.ReadFile(publicKeyFile)
	if err != nil {
		return fmt.Errorf("failed to read public key: %v", err)
	}
	publicKeyPEM, _ := pem.Decode(publicKeyBytes)
	parsedPublicKey, err := x509.ParsePKIXPublicKey(publicKeyPEM.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %v", err)
	}
	var ok bool
	publicKey, ok = parsedPublicKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("failed to cast public key to RSA public key")
	}

	log.Println("RSA keys loaded successfully")
	return nil
}

// generateRSAKeys generates a new RSA key pair and saves them to files
func generateRSAKeys() error {
	// Generate private key
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %v", err)
	}

	// Encode private key to PEM format
	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}

	// Save private key to file
	privateKeyFile, err := os.Create(privateKeyFile)
	if err != nil {
		return fmt.Errorf("failed to create private key file: %v", err)
	}
	defer privateKeyFile.Close()
	if err := pem.Encode(privateKeyFile, privateKeyPEM); err != nil {
		return fmt.Errorf("failed to write private key to file: %v", err)
	}

	// Encode public key to PEM format
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %v", err)
	}
	publicKeyPEM := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}

	// Save public key to file
	publicKeyFile, err := os.Create(publicKeyFile)
	if err != nil {
		return fmt.Errorf("failed to create public key file: %v", err)
	}
	defer publicKeyFile.Close()
	if err := pem.Encode(publicKeyFile, publicKeyPEM); err != nil {
		return fmt.Errorf("failed to write public key to file: %v", err)
	}

	log.Println("RSA key pair generated and saved successfully")
	return nil
}

// createTokenPair generates a new access token and refresh token pair
func createTokenPair(username string, userID uint) (TokenPair, error) {
	accessToken, err := createAccessToken(username)
	if err != nil {
		return TokenPair{}, err
	}

	refreshToken := uuid.New().String()
	expiryTime := time.Now().Add(7 * 24 * time.Hour)

	newRefreshToken := RefreshToken{
		Token:  refreshToken,
		UserID: userID,
		Expiry: expiryTime,
	}

	result := db.Create(&newRefreshToken)
	if result.Error != nil {
		return TokenPair{}, result.Error
	}

	return TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

// createAccessToken generates a new JWT access token
func createAccessToken(username string) (string, error) {
	expirationTime := time.Now().Add(15 * time.Minute)
	claims := &Claims{
		Username: username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(privateKey)
}

// tokenMiddleware is a middleware function to verify the JWT token in the request header
func tokenMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Authorization header is required", http.StatusUnauthorized)
			return
		}

		bearerToken := strings.Split(authHeader, " ")
		if len(bearerToken) != 2 || bearerToken[0] != "Bearer" {
			http.Error(w, "Invalid authorization header format", http.StatusUnauthorized)
			return
		}

		token := bearerToken[1]
		claims, err := verifyToken(token)
		if err != nil {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		// Add the username to the request context
		ctx := context.WithValue(r.Context(), "username", claims.Username)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

// testEndpoint is a protected endpoint that requires a valid JWT token
func testEndpoint(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(map[string]string{"result": "ok"})
}

// verifyToken verifies the JWT token and returns the claims
func verifyToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return publicKey, nil
	})
	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token")
}
