package controller

import (
	"fmt"
	"encoding/json"
	"net/http"
	"time"
	"github.com/rb4807/Golang-Utlis/auth"
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

// Handlers

func RegisterHandler(authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req RegisterRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

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
}

func LoginHandler(authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req LoginRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}
		user, token, err := authService.Login(req.Username, req.Password)
		if err != nil {
			fmt.Println("Error",err)
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
}

func ProfileHandler(authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims, err := auth.GetUserFromContext(r.Context())
		if err != nil {
			http.Error(w, "User not found", http.StatusUnauthorized)
			return
		}

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
			"is_superuser": user.IsSuperuser,
			"date_joined":  user.DateJoined,
			"last_login":   user.LastLogin,
		})
	}
}

func AdminHandler(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.GetUserFromContext(r.Context())

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":  "Welcome to the admin area",
		"user_id":  claims.UserID,
		"username": claims.Username,
	})
}

func SuperuserHandler(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.GetUserFromContext(r.Context())

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":  "Welcome to the superuser area",
		"user_id":  claims.UserID,
		"username": claims.Username,
	})
}
