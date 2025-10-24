package handlers

import (
	email2 "app/helpers/email"
	"app/helpers/logs"
	"app/helpers/users"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/mail"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	gonanoid "github.com/matoous/go-nanoid/v2"
)

func EmailVerificationHandler(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	// Get token & hash it
	rawToken := chi.URLParam(r, "token")
	token := users.HashToken(rawToken)

	// Get user ID from token & delete the token
	var userID int64
	err := db.QueryRow(`DELETE FROM verification_tokens WHERE token_hash = $1 RETURNING user_id`, token).
		Scan(&userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			w.WriteHeader(http.StatusNotFound)
		} else {
			logs.Err(
				db,
				"DB err",
				"Failed to query the DB",
				err,
				map[string]any{
					"route": r.URL.Path,
				},
				userID,
			)
			w.WriteHeader(http.StatusInternalServerError)
		}
		return
	}

	// Update the user's email_verified
	_, err = db.Exec(`UPDATE users SET email_verified = TRUE WHERE id = $1`, userID)
	if err != nil {
		logs.Err(
			db,
			"DB err",
			"Failed to query the DB",
			err,
			map[string]any{
				"route": r.URL.Path,
			},
			userID,
		)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func ResendEmailVerificationHandler(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	// Payload
	type Payload struct {
		Email string `json:"email"`
	}
	var p Payload

	// Decode
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	err := dec.Decode(&p)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	defer func() {
		_ = r.Body.Close()
	}()

	// Format email
	email := strings.TrimSpace(strings.ToLower(p.Email))
	_, err = mail.ParseAddress(email)
	if err != nil {
		w.WriteHeader(http.StatusUnprocessableEntity)
		return
	}

	// Check the user's email_verified
	var userID int64
	var verified bool
	err = db.QueryRow(`SELECT id, email_verified FROM users WHERE email = $1`, email).Scan(&userID, &verified)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			w.WriteHeader(http.StatusNoContent) // Fake OK
		} else {
			logs.Err(
				db,
				"DB err",
				"Failed to query the DB",
				err,
				map[string]any{
					"route":    r.URL.Path,
					"email":    email,
					"verified": verified,
				},
				userID,
			)
			w.WriteHeader(http.StatusInternalServerError)
		}
		return
	}
	if verified {
		w.WriteHeader(http.StatusNoContent) // Fake OK
		return
	}

	// Check existing token timestamp
	var lastSent time.Time
	err = db.QueryRow(`
		SELECT created_at
		FROM verification_tokens
		WHERE user_id = $1
		`, userID).Scan(&lastSent)
	if err == nil {
		if time.Since(lastSent) < time.Hour {
			w.WriteHeader(http.StatusNoContent) // Fake OK if last sent <1h ago (prevent spam)
			return
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		logs.Err(
			db,
			"DB err",
			"Failed to query the DB",
			err,
			map[string]any{
				"route":     r.URL.Path,
				"payload":   p,
				"last_sent": lastSent,
			},
			userID,
		)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Generate a new verification token & hash it
	rawToken, err := gonanoid.New(128)
	if err != nil {
		logs.Err(
			db,
			"Gonanoid gen err",
			"Gonanoid failed to generate the token",
			err,
			map[string]any{
				"route":   r.URL.Path,
				"payload": p,
			},
			userID,
		)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	tokenHash := users.HashToken(rawToken)

	// Store the verification token
	_, err = db.Exec(`
		INSERT INTO verification_tokens(user_id, token_hash)
		VALUES ($1, $2)
		ON CONFLICT (user_id)
		DO UPDATE SET token_hash = EXCLUDED.token_hash, created_at = NOW()
	`, userID, tokenHash)
	if err != nil {
		logs.Err(
			db,
			"DB err",
			"Failed to query the DB",
			err,
			map[string]any{
				"route":   r.URL.Path,
				"payload": p,
			},
			userID,
		)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Send the verification email
	go func() {
		frontend := os.Getenv("FRONTEND_URL")
		u := fmt.Sprintf("%s/auth/verify?token=%s", frontend, url.PathEscape(rawToken))
		err := email2.SendVerification(email, u)
		if err != nil {
			logs.Err(
				db,
				"SMTP err",
				"Failed to send mail",
				err,
				map[string]any{
					"route": r.URL.Path,
					"email": email,
					"url":   u,
				},
				userID,
			)
			return
		}
	}()

	w.WriteHeader(http.StatusNoContent)
}
