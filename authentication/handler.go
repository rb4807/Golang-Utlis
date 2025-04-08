package authentication

import (
	"database/sql"
	"errors"
	"time"
)

func (s *Service) Register(user User, password string) (int64, error) {
	// Validate user data
	if err := s.validate(user); err != nil {
		return 0, err
	}

	// Hash password
	hashedPassword, err := s.HashPassword(password)
	if err != nil {
		return 0, err
	}

	// Insert user into database
	query := `
		INSERT INTO users (username, email, password, first_name, last_name, is_active, is_superuser, date_joined)
		VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
		RETURNING id
	`
	var userID int64
	err = s.config.DBConnection.QueryRow(
		query,
		user.Username,
		user.Email,
		hashedPassword,
		user.FirstName,
		user.LastName,
		user.IsActive,
		user.IsSuperuser,
	).Scan(&userID)
	
	if err != nil {
		return 0, err
	}
	
	return userID, nil
}

// Authenticate verifies a user's credentials
func (s *Service) Authenticate(username, password string) (*User, error) {
	query := `
		SELECT id, username, email, password, first_name, last_name, is_active, is_superuser, date_joined, last_login, password_changed
		FROM users
		WHERE (username = $1 OR email = $1) AND is_active = true
	`
	
	var user User
	err := s.config.DBConnection.QueryRow(query, username).Scan(
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
			return nil, ErrInvalidCredentials
		}
		return nil, err
	}
	
	// Verify password
	if !s.VerifyPassword(user.Password, password) {
		return nil, ErrInvalidCredentials
	}
	
	// Update last login time
	_, err = s.config.DBConnection.Exec(
		"UPDATE users SET last_login = NOW() WHERE id = $1",
		user.ID,
	)
	if err != nil {
		return nil, err
	}
	
	return &user, nil
}

// Login combines authentication and JWT generation
func (s *Service) Login(username, password string) (*User, string, error) {
	user, err := s.Authenticate(username, password)
	if err != nil {
		return nil, "", err
	}
	
	token, err := s.GenerateJWT(user)
	if err != nil {
		return user, "", err
	}
	
	return user, token, nil
}

// GenerateOTP creates a one-time password for a user
func (s *Service) GenerateOTP(userID int64, length int, validityMinutes int) (string, error) {
	if length <= 0 {
		length = 6 // Default OTP length
	}
	if validityMinutes <= 0 {
		validityMinutes = 15 // Default validity: 15 minutes
	}
	
	// Check if user exists
	exists, err := s.userExists(userID)
	if err != nil {
		return "", err
	}
	if !exists {
		return "", ErrUserNotFound
	}
	
	// Generate random OTP
	otp, err := s.generateRandomOTP(length)
	if err != nil {
		return "", err
	}
	
	// Store OTP in database
	expiresAt := time.Now().Add(time.Duration(validityMinutes) * time.Minute)
	
	// Delete any existing OTPs for this user
	_, err = s.config.DBConnection.Exec("DELETE FROM otp WHERE user_id = $1", userID)
	if err != nil {
		return "", err
	}
	
	// Insert new OTP
	_, err = s.config.DBConnection.Exec(
		"INSERT INTO otp (user_id, otp, expires_at) VALUES ($1, $2, $3)",
		userID, otp, expiresAt,
	)
	if err != nil {
		return "", err
	}
	
	return otp, nil
}

// VerifyOTP checks if an OTP is valid for a user
func (s *Service) VerifyOTP(userID int64, otp string) (bool, error) {
	query := `
		SELECT id FROM otp
		WHERE user_id = $1 AND otp = $2 AND expires_at > NOW() AND verified = false
	`
	
	var otpID int64
	err := s.config.DBConnection.QueryRow(query, userID, otp).Scan(&otpID)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, err
	}
	
	// Mark OTP as verified
	_, err = s.config.DBConnection.Exec("UPDATE otp SET verified = true WHERE id = $1", otpID)
	if err != nil {
		return false, err
	}
	
	return true, nil
}

// ChangePassword updates a user's password
func (s *Service) ChangePassword(userID int64, currentPassword, newPassword string) error {
	// Get current user details
	var storedPassword string
	err := s.config.DBConnection.QueryRow("SELECT password FROM users WHERE id = $1", userID).Scan(&storedPassword)
	if err != nil {
		if err == sql.ErrNoRows {
			return ErrUserNotFound
		}
		return err
	}
	
	// Verify current password
	if !s.VerifyPassword(storedPassword, currentPassword) {
		return ErrInvalidPassword
	}
	
	// Hash new password
	hashedPassword, err := s.HashPassword(newPassword)
	if err != nil {
		return err
	}
	
	// Update password
	_, err = s.config.DBConnection.Exec(
		"UPDATE users SET password = $1, password_changed = NOW() WHERE id = $2",
		hashedPassword, userID,
	)
	
	return err
}

// ResetPassword resets a user's password (admin function or after verification)
func (s *Service) ResetPassword(userID int64, newPassword string) error {
	// Check if user exists
	exists, err := s.userExists(userID)
	if err != nil {
		return err
	}
	if !exists {
		return ErrUserNotFound
	}
	
	// Hash new password
	hashedPassword, err := s.HashPassword(newPassword)
	if err != nil {
		return err
	}
	
	// Update password
	_, err = s.config.DBConnection.Exec(
		"UPDATE users SET password = $1, password_changed = NOW() WHERE id = $2",
		hashedPassword, userID,
	)
	
	return err
}

// userExists checks if a user exists by ID
func (s *Service) userExists(userID int64) (bool, error) {
	var exists bool
	err := s.config.DBConnection.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE id = $1)", userID).Scan(&exists)
	return exists, err
}