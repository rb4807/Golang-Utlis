package auth

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"math/big"
	"strings"
	"regexp"
	"github.com/go-playground/validator/v10"
	"golang.org/x/crypto/bcrypt"
)

// Context key for storing user info in request context
type contextKey string
const UserContextKey contextKey = "user"

// Common errors
var (
	ErrInvalidCredentials = errors.New("invalid username or password")
	ErrUserNotFound       = errors.New("user not found")
	ErrInvalidPassword    = errors.New("current password is incorrect")
	ErrUserNotInContext   = errors.New("user not found in context")
	ErrConfigInvalid      = errors.New("configuration is invalid")
)

// NewService creates a new authentication service
func NewService(config Config) (*Service, error) {
	if config.JWTSecret == "" {
		return nil, errors.New("JWT secret is required")
	}
	if config.DBConnection == nil {
		return nil, errors.New("DB connection is required")
	}
	
	validate := validator.New()
	
	return &Service{
		config:    config,
		validator: validate,
	}, nil
}

// validate a struct using the validator
func (s *Service) validate(data interface{}) error {
	return s.validator.(*validator.Validate).Struct(data)
}

// HashPassword hashes a password using bcrypt
func (s *Service) HashPassword(password string) (string, error) {
	hashedBytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedBytes), nil
}

// VerifyPassword checks if a password matches the hash
func (s *Service) VerifyPassword(hashedPassword, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	return err == nil
}

// generateRandomOTP creates a random numeric OTP of specified length
func (s *Service) generateRandomOTP(length int) (string, error) {
	otp := ""
	for i := 0; i < length; i++ {
		n, err := rand.Int(rand.Reader, big.NewInt(10))
		if err != nil {
			return "", err
		}
		otp += fmt.Sprintf("%d", n.Int64())
	}
	return otp, nil
}

// IsAuthenticated checks if a request is authenticated
func (s *Service) IsAuthenticated(r *http.Request) bool {
	_, err := GetUserFromContext(r.Context())
	return err == nil
}

// AddUserToContext adds user claims to a context
func AddUserToContext(ctx context.Context, claims *TokenClaims) context.Context {
	return context.WithValue(ctx, UserContextKey, claims)
}

// ValidateEmail checks if an email is well-formed
func ValidateEmail(email string) bool {
	// Use validator to check email
	validate := validator.New()
	err := validate.Var(email, "required,email")
	return err == nil
}

// SanitizeUsername removes potentially harmful characters from username
func SanitizeUsername(username string) string {
	// This is a simple implementation
	// In a production system, you might want more sophisticated sanitization
	sanitized := strings.TrimSpace(username)
	// Remove any characters that aren't alphanumeric, underscore, or period
	sanitized = regexp.MustCompile(`[^a-zA-Z0-9_.]+`).ReplaceAllString(sanitized, "")
	return sanitized
}

