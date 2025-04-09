package auth

import (
	"errors"
	"fmt"
	"time"
	"github.com/dgrijalva/jwt-go"
)

// TokenClaims represents the JWT token claims
type TokenClaims struct {
	UserID      int64  `json:"user_id"`
	Username    string `json:"username"`
	IsSuperuser bool   `json:"is_superuser"`
	jwt.StandardClaims
}

// GenerateJWT creates a new JWT token for the user
func (s *Service) GenerateJWT(user *User) (string, error) {
	claims := TokenClaims{
		UserID:      user.ID,
		Username:    user.Username,
		IsSuperuser: user.IsSuperuser,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(s.config.TokenDuration).Unix(),
			IssuedAt:  time.Now().Unix(),
		},
	}
	
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString([]byte(s.config.JWTSecret))
	if err != nil {
		return "", err
	}
	
	return signedToken, nil
}

// VerifyJWT validates a JWT token and returns the claims
func (s *Service) VerifyJWT(tokenString string) (*TokenClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(s.config.JWTSecret), nil
	})
	
	if err != nil {
		return nil, err
	}
	
	if claims, ok := token.Claims.(*TokenClaims); ok && token.Valid {
		return claims, nil
	}
	
	return nil, errors.New("invalid token")
}

// RefreshJWT creates a new token with extended expiration time
func (s *Service) RefreshJWT(tokenString string) (string, error) {
	// First verify the existing token
	claims, err := s.VerifyJWT(tokenString)
	if err != nil {
		return "", err
	}
	
	// Create new token with same claims but new expiration
	claims.StandardClaims.ExpiresAt = time.Now().Add(s.config.TokenDuration).Unix()
	claims.StandardClaims.IssuedAt = time.Now().Unix()
	
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString([]byte(s.config.JWTSecret))
	if err != nil {
		return "", err
	}
	
	return signedToken, nil
}

// GetUserIDFromToken extracts the user ID from a token string
func (s *Service) GetUserIDFromToken(tokenString string) (int64, error) {
	claims, err := s.VerifyJWT(tokenString)
	if err != nil {
		return 0, err
	}
	return claims.UserID, nil
}