package db

// POSTGRES CONNECTION

import (
	"database/sql"
	"fmt"
	"log"
	"os"

	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

func InitDB() *sql.DB {
	// Load .env file
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found (proceeding with system env variables)")
	}

	// Get environment variables
	dbUser := os.Getenv("DB_USER")
	dbPassword := os.Getenv("DB_PASSWORD")
	dbHost := os.Getenv("DB_HOST")
	dbPort := os.Getenv("DB_PORT")
	dbName := os.Getenv("DB_NAME")
	sslMode := os.Getenv("DB_SSLMODE") // Optional: fallback to "disable" or "require"

	if sslMode == "" {
		sslMode = "disable"
	}

	// Build DSN string
	dsn := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=%s",
		dbUser, dbPassword, dbHost, dbPort, dbName, sslMode)

	// Connect to PostgreSQL
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	if err := db.Ping(); err != nil {
		log.Fatalf("Failed to ping database: %v", err)
	}

	fmt.Println("Database connected successfully")
	return db
}

// MYSQL CONNECTION

// import (
// 	"database/sql"
// 	"fmt"
// 	"log"
// 	"os"
// 	"github.com/joho/godotenv"
// 	_ "github.com/go-sql-driver/mysql"
// )

// func InitDB() *sql.DB {
// 	// Load .env file
// 	if err := godotenv.Load(); err != nil {
// 		log.Println("No .env file found (proceeding with system env variables)")
// 	}

// 	// Get environment variables
// 	dbUser := os.Getenv("DB_USER")
// 	dbPassword := os.Getenv("DB_PASSWORD")
// 	dbHost := os.Getenv("DB_HOST")
// 	dbPort := os.Getenv("DB_PORT")
// 	dbName := os.Getenv("DB_NAME")

// 	// Build DSN string
// 	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?parseTime=true",
// 		dbUser, dbPassword, dbHost, dbPort, dbName)

// 	// Connect to MySQL
// 	db, err := sql.Open("mysql", dsn)
// 	if err != nil {
// 		log.Fatalf("Failed to connect to database: %v", err)
// 	}

// 	if err := db.Ping(); err != nil {
// 		log.Fatalf("Failed to ping database: %v", err)
// 	}

// 	fmt.Println("Database connected successfully")
// 	return db
// }
