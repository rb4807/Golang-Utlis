package router

import (
	"net/http"

	"github.com/rb4807/Golang-Utlis/auth"
	"github.com/rb4807/Golang-Utlis/controller"
)

func SetupRoutes(authService *auth.Service) *http.ServeMux {
	mux := http.NewServeMux()

	// Public routes
	mux.HandleFunc("/register", controller.RegisterHandler(authService))
	mux.HandleFunc("/login", controller.LoginHandler(authService))

	// Protected routes
	mux.Handle("/profile", authService.AuthMiddleware(http.HandlerFunc(controller.ProfileHandler(authService))))
	mux.Handle("/admin", authService.AdminMiddleware(http.HandlerFunc(controller.AdminHandler)))
	mux.Handle("/superuser", authService.SuperuserMiddleware(http.HandlerFunc(controller.SuperuserHandler)))

	return mux
}
