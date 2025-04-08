package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
	"github.com/your-username/go-auth/auth" // Import the auth package
	_ "github.com/lib/pq"
)

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type RegisterRequest struct {
	Username  string `json:"username"`
	Email     string `json:"email"`
	Password  string `json:"password"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
}

type TokenResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	UserID    int64     `json:"user_id"`
}

var authService *auth.Service

func main() {
	// Connect to database
	db, err := sql.Open("postgres", "postgres://user:password@localhost/auth_db?sslmode=disable")
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	// Initialize database tables
	if err := auth.InitDB(db); err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}

	// Create authentication service
	authService, err = auth.NewService(auth.Config{
		JWTSecret:     "your-secret-key", // Use environment variables in production
		TokenDuration: 24 * time.Hour,    // 24 hours
		DBConnection:  db,
	})
	if err != nil {
		log.Fatalf("Failed to create authentication service: %v", err)
	}

	// Set up routes
	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/login", loginHandler)
	
	// Protected routes
	http.Handle("/profile", authService.AuthMiddleware(http.HandlerFunc(profileHandler)))
	http.Handle("/admin", authService.AdminMiddleware(http.HandlerFunc(adminHandler)))
	http.Handle("/superuser", authService.SuperuserMiddleware(http.HandlerFunc(superuserHandler)))

	// Start server
	fmt.Println("Server starting on port 8080...")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Create user
	user := auth.User{
		Username:  req.Username,
		Email:     req.Email,
		FirstName: req.FirstName,
		LastName:  req.LastName,
		IsActive:  true,
	}

	userID, err := authService.Register(user, req.Password)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"user_id":  userID,
		"username": req.Username,
		"message":  "User registered successfully",
	})
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Use the combined login function
	user, token, err := authService.Login(req.Username, req.Password)
	if err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	expiresAt := time.Now().Add(24 * time.Hour)
	response := TokenResponse{
		Token:     token,
		ExpiresAt: expiresAt,
		UserID:    user.ID,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func profileHandler(w http.ResponseWriter, r *http.Request) {
	// Get user from context
	claims, err := auth.GetUserFromContext(r.Context())
	if err != nil {
		http.Error(w, "User not found", http.StatusUnauthorized)
		return
	}

	// Get user details
	user, err := authService.GetUserByID(claims.UserID)
	if err != nil {
		http.Error(w, "Error retrieving user", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"user_id":      user.ID,
		"username":     user.Username,
		"email":        user.Email,
		"first_name":   user.FirstName,
		"last_name":    user.LastName,
		"is_staff":     user.IsStaff,
		"is_superuser": user.IsSuperuser,
		"date_joined":  user.DateJoined,
		"last_login":   user.LastLogin,
	})
}

func adminHandler(w http.ResponseWriter, r *http.Request) {
	// This handler is only accessible to staff and superusers
	claims, _ := auth.GetUserFromContext(r.Context())

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":  "Welcome to the admin area",
		"user_id":  claims.UserID,
		"username": claims.Username,
	})
}

func superuserHandler(w http.ResponseWriter, r *http.Request) {
	// This handler is only accessible to superusers
	claims, _ := auth.GetUserFromContext(r.Context())

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":  "Welcome to the superuser area",
		"user_id":  claims.UserID,
		"username": claims.Username,
	})
}