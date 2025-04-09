package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/rb4807/Golang-Utlis/auth"
	"github.com/rb4807/Golang-Utlis/db"
	"github.com/rb4807/Golang-Utlis/router"
)

func main() {
	// Connect to database
	database := db.InitDB()
	defer database.Close()

	// Initialize auth DB
	if err := auth.InitDB(database); err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}

	// Initialize auth service
	authService, err := auth.NewService(auth.Config{
		JWTSecret:     "your-secret-key",
		TokenDuration: 24 * time.Hour,
		DBConnection:  database,
	})
	if err != nil {
		log.Fatalf("Failed to create authentication service: %v", err)
	}

	// Set up routes
	r := router.SetupRoutes(authService)

	// Start server
	fmt.Println("Server starting on port 8080...")
	log.Fatal(http.ListenAndServe(":8080", r))
}
