package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"strings"
	"time"
)

func HashPassword(password string) (string, error) {
	bcryptHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(bcryptHash), nil
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if err != nil {
		return false
	}
	return true
}

func MakeJWT(userID uuid.UUID, tokenSecret string, expiresIn time.Duration) (string, error) {
	signedToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Issuer:    "chirpy",
		Subject:   userID.String(),
		ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(expiresIn)),
		IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
	}).SignedString([]byte(tokenSecret))
	if err != nil {
		return "", err
	}
	return signedToken, nil
}

func ValidateJWT(tokenString, tokenSecret string) (uuid.UUID, error) {
	token, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(tokenSecret), nil
	})
	if err != nil {
		return uuid.Nil, err
	}
	tokenClaims, ok := token.Claims.(*jwt.RegisteredClaims)
	if !ok {
		return uuid.Nil, errors.New("invalid token")
	}
	tokenID, err := uuid.Parse(tokenClaims.Subject)
	if err != nil {
		return uuid.Nil, err
	}
	return tokenID, nil
}

func GetBearerToken(headers http.Header) (string, error) {
	headerString := headers.Get("Authorization")
	if headerString == "" {
		return "", errors.New("authorization header not found")
	}
	tokenString, found := strings.CutPrefix(headerString, "Bearer")
	if !found {
		return "", errors.New("invalid token")
	}
	return strings.TrimSpace(tokenString), nil

}

func MakeRefreshToken() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func GetApiKey(headers http.Header) (string, error) {
	headerString := headers.Get("Authorization")
	if headerString == "" {
		return "", errors.New("authorization header not found")
	}
	tokenString, found := strings.CutPrefix(headerString, "ApiKey")
	if !found {
		return "", errors.New("invalid token")
	}
	return strings.TrimSpace(tokenString), nil
}
