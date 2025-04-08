package authentication

import (
	"database/sql"
	"time"
)

type User struct {
	ID              int64     `json:"id"`
	Username        string    `json:"username" validate:"required,min=3,max=50"`
	Email           string    `json:"email" validate:"required,email"`
	Password        string    `json:"-"` // Hashed password, never expose in JSON
	FirstName       string    `json:"first_name"`
	LastName        string    `json:"last_name"`
	IsActive        bool      `json:"is_active"`
	IsSuperuser     bool      `json:"is_superuser"`
	DateJoined      time.Time `json:"date_joined"`
	LastLogin       time.Time `json:"last_login"`
	PasswordChanged time.Time `json:"password_changed"`
}

// OTPData stores OTP information
type OTPData struct {
	Value     string
	ExpiresAt time.Time
	Verified  bool
}

// Config holds the configuration for the authentication package
type Config struct {
	JWTSecret     string
	TokenDuration time.Duration
	DBConnection  *sql.DB
}

// Service provides authentication functionality
type Service struct {
	config    Config
	validator interface{} 
}

// Initialize database tables (similar to Django migrations)
func InitDB(db *sql.DB) error {
	// Create users table
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id SERIAL PRIMARY KEY,
			username VARCHAR(50) UNIQUE NOT NULL,
			email VARCHAR(100) UNIQUE NOT NULL,
			password VARCHAR(255) NOT NULL,
			first_name VARCHAR(50),
			last_name VARCHAR(50),
			is_active BOOLEAN DEFAULT TRUE,
			is_superuser BOOLEAN DEFAULT FALSE,
			date_joined TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			last_login TIMESTAMP,
			password_changed TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		return err
	}

	// Create OTP table
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS users_otp (
			id SERIAL PRIMARY KEY,
			user_id INTEGER REFERENCES users(id),
			otp VARCHAR(10) NOT NULL,
			expires_at TIMESTAMP NOT NULL,
			verified BOOLEAN DEFAULT FALSE
		)
	`)
	return err
}

// GetUserByID retrieves a user by ID
func (s *Service) GetUserByID(userID int64) (*User, error) {
	query := `
		SELECT id, username, email, password, first_name, last_name, is_active, is_superuser, date_joined, last_login, password_changed
		FROM users
		WHERE id = $1
	`
	
	var user User
	err := s.config.DBConnection.QueryRow(query, userID).Scan(
		&user.ID,
		&user.Username,
		&user.Email,
		&user.Password,
		&user.FirstName,
		&user.LastName,
		&user.IsActive,
		&user.IsSuperuser,
		&user.DateJoined,
		&user.LastLogin,
		&user.PasswordChanged,
	)
	
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	
	return &user, nil
}

// UpdateUser updates user information
func (s *Service) UpdateUser(user *User) error {
	query := `
		UPDATE users
		SET username = $1, email = $2, first_name = $3, last_name = $4, is_active = $5, is_superuser = $6
		WHERE id = $7
	`
	
	_, err := s.config.DBConnection.Exec(
		query,
		user.Username,
		user.Email,
		user.FirstName,
		user.LastName,
		user.IsActive,
		user.IsSuperuser,
		user.ID,
	)
	
	return err
}