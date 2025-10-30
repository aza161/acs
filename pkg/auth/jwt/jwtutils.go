package jwtutils

import (
	"errors"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const jwtExpirationTimeInMinutes time.Duration = 2

// A function used to generate JWT tokens signed by Ed25519 private key in .pem format.
// privateKey is the directory for the .pem file.
// sub is the subject claim, usually the user identifier.
// you can use this command to generate an ed25519 key:
// $ openssl genpkey -algorithm Ed25519 -out ed25519pkey.pem
// To generate the associated public key you can use the following command:
// $ openssl pkey -in ed25519pkey.pem -pubout -out ed25519pubkey.pem
// Note: The only claim in this token is the expiry time.
func GenerateJWTEd25519(sub, privateKey string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(jwtExpirationTimeInMinutes * time.Minute)),
		Subject:   sub,
	})

	pem, err := os.ReadFile(privateKey)
	if err != nil {
		return "", errors.New("error when reading private key")
	}

	key, err := jwt.ParseEdPrivateKeyFromPEM(pem)

	if err != nil {
		return "", err
	}

	ss, err := token.SignedString(key)

	return ss, err
}

// A function used to parse a JWT string signed by an Ed25519 private key and verify it.
// It takes a publicKey directory for a .pem Ed25519 public key.
// Check the documentation of GenerateJWTEd25519() to know how to generate these keys.
func ParseJWTEd25519(tokenStr, publicKey string) (*jwt.Token, error) {
	parser := jwt.NewParser(jwt.WithExpirationRequired())
	token, err := parser.Parse(tokenStr, func(token *jwt.Token) (any, error) {
		pem, err := os.ReadFile(publicKey)
		if err != nil {
			return nil, errors.New("error when reading public key")
		}
		key, err := jwt.ParseEdPublicKeyFromPEM(pem)
		if err != nil {
			return nil, errors.New("error when reading public key")
		}
		return key, nil
	})
	return token, err
}
