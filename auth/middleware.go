package auth

import (
	"context"
	"net/http"
	"strings"
)

// AuthMiddleware is a middleware function to protect routes
func (s *Service) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get token from Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Authorization header is required", http.StatusUnauthorized)
			return
		}
		
		// Expected format: "Bearer <token>"
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			http.Error(w, "Authorization header format must be Bearer <token>", http.StatusUnauthorized)
			return
		}
		
		// Verify token
		claims, err := s.VerifyJWT(parts[1])
		if err != nil {
			http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
			return
		}
		
		// Add claims to request context
		ctx := context.WithValue(r.Context(), UserContextKey, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// AdminMiddleware is a middleware function to protect admin routes
func (s *Service) AdminMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// First apply auth middleware
		s.AuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check if user is staff or superuser
			claims := r.Context().Value(UserContextKey).(*TokenClaims)
			if !claims.IsSuperuser {
				http.Error(w, "Admin access required", http.StatusForbidden)
				return
			}
			
			next.ServeHTTP(w, r)
		})).ServeHTTP(w, r)
	})
}

// SuperuserMiddleware is a middleware function to protect superuser routes
func (s *Service) SuperuserMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// First apply auth middleware
		s.AuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check if user is superuser
			claims := r.Context().Value(UserContextKey).(*TokenClaims)
			if !claims.IsSuperuser {
				http.Error(w, "Superuser access required", http.StatusForbidden)
				return
			}
			
			next.ServeHTTP(w, r)
		})).ServeHTTP(w, r)
	})
}

// GetUserFromContext extracts user claims from request context
func GetUserFromContext(ctx context.Context) (*TokenClaims, error) {
	user, ok := ctx.Value(UserContextKey).(*TokenClaims)
	if !ok {
		return nil, ErrUserNotInContext
	}
	return user, nil
}

// RequireAuth is a middleware generator that can be used to protect routes with custom logic
func (s *Service) RequireAuth(checkFunc func(*TokenClaims) bool, message string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			s.AuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				claims := r.Context().Value(UserContextKey).(*TokenClaims)
				if !checkFunc(claims) {
					http.Error(w, message, http.StatusForbidden)
					return
				}
				next.ServeHTTP(w, r)
			})).ServeHTTP(w, r)
		})
	}
}