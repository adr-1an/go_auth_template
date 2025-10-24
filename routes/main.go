package routes

import (
	"app/handlers"
	"app/mw"
	"database/sql"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/sony/sonyflake"
)

func NewRouter(db *sql.DB, sf *sonyflake.Sonyflake) chi.Router {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(mw.RecoverAndLog(db))
	r.Use(middleware.Timeout(15 * time.Second))
	r.Use(mw.MaxBody(1 << 20))
	r.Use(middleware.Heartbeat("/ping"))
	r.Use(middleware.SetHeader("Content-Type", "application/json"))

	// CORS
	allowed := strings.Split(os.Getenv("ALLOWED_DOMAINS"), ",")
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   allowed,
		AllowedMethods:   []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Oh~ h-hi pal!"))
	})

	// API v1
	r.Route("/v1", func(r chi.Router) {
		// Auth
		r.Route("/auth", func(r chi.Router) {
			// Registration
			r.Post("/register", func(w http.ResponseWriter, r *http.Request) { handlers.RegistrationHandler(w, r, sf, db) })

			// Login
			r.Post("/login", func(w http.ResponseWriter, r *http.Request) { handlers.LoginHandler(w, r, sf, db) })

			// Token check
			r.Get("/check", func(w http.ResponseWriter, r *http.Request) { handlers.TokenCheckHandler(w, r, db) })

			// Logout
			r.Delete("/logout", func(w http.ResponseWriter, r *http.Request) { handlers.LogoutHandler(w, r, db) })

			// Send password reset email
			r.Post("/forgot", func(w http.ResponseWriter, r *http.Request) { handlers.SendPasswordResetHandler(w, r, db) })

			// Reset password
			r.Put("/password/{token}", func(w http.ResponseWriter, r *http.Request) { handlers.PasswordResetHandler(w, r, db) })

			// Change password
			r.Put("/password", func(w http.ResponseWriter, r *http.Request) { handlers.PasswordChangeHandler(w, r, db) })

			// Verification
			r.Route("/verifications", func(r chi.Router) {
				// Email verification
				r.Put("/{token}", func(w http.ResponseWriter, r *http.Request) { handlers.EmailVerificationHandler(w, r, db) })

				// Resend email verification
				r.Post("/", func(w http.ResponseWriter, r *http.Request) { handlers.ResendEmailVerificationHandler(w, r, db) })
			})
		})

		// Profile
		r.Route("/profile", func(r chi.Router) {
			// View profile
			r.Get("/", func(w http.ResponseWriter, r *http.Request) { handlers.ProfileHandler(w, r, db) })

			// Update profile
			r.Patch("/", func(w http.ResponseWriter, r *http.Request) { handlers.UpdateProfileHandler(w, r, db) })

			// Send email update confirmation
			r.Post("/email", func(w http.ResponseWriter, r *http.Request) { handlers.RequestEmailChangeHandler(w, r, db) })

			// Update email
			r.Put("/email/{token}", func(w http.ResponseWriter, r *http.Request) { handlers.UpdateEmail(w, r, db) })
		})
	})

	return r
}
