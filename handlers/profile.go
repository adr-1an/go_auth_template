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
	"github.com/matoous/go-nanoid/v2"
)

func ProfileHandler(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	// Get token
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if token == "" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Get user ID from token
	userID, err := users.GetId(token, w, db)
	if err != nil {
		return
	}

	// User struct
	type User struct {
		ID    string `json:"id"`
		Name  string `json:"name"`
		Email string `json:"email"`
	}
	var u User

	// Get user data
	err = db.QueryRow(`SELECT id, name, email FROM users WHERE id = $1`, userID).Scan(&u.ID, &u.Name, &u.Email)
	if err != nil {
		logs.Err(
			db,
			"DB err",
			"Failed to query the DB.",
			err,
			"",
			userID)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Return the user data
	w.WriteHeader(http.StatusOK)
	if err = json.NewEncoder(w).Encode(map[string]interface{}{
		"user": u,
	}); err != nil {
		logs.Err(
			db,
			"Return err",
			"Failed to return the data.",
			err,
			map[string]any{
				"user": u,
			},
			userID,
		)
	}
}

func UpdateProfileHandler(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	// Get token
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if token == "" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Get user ID from token
	userID, err := users.GetId(token, w, db)
	if err != nil {
		return
	}

	// Payload
	type Payload struct {
		Name string `json:"name"`
	}
	var p Payload

	// Decode
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	err = dec.Decode(&p)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Validate
	if len(p.Name) > 64 {
		w.WriteHeader(http.StatusUnprocessableEntity)
		return
	}

	// Update the user
	_, err = db.Exec(`UPDATE users SET name = $1 WHERE id = $2`, p.Name, userID)
	if err != nil {
		logs.Err(
			db,
			"DB err",
			"Failed to query the DB.",
			err,
			map[string]any{
				"payload": p,
			},
			userID,
		)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// RequestEmailChangeHandler - Creates & sends an email change link when the user requests it
func RequestEmailChangeHandler(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	// Get token
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if token == "" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Get user ID from token
	userID, err := users.GetId(token, w, db)
	if err != nil {
		return
	}

	// Payload
	type Payload struct {
		Email string `json:"email"`
	}
	var p Payload

	// Decode
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	err = dec.Decode(&p)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Validate & format email
	email := strings.TrimSpace(strings.ToLower(p.Email))
	if len(email) > 254 {
		w.WriteHeader(http.StatusUnprocessableEntity)
		return
	}
	_, err = mail.ParseAddress(email)
	if err != nil {
		w.WriteHeader(http.StatusUnprocessableEntity)
		return
	}

	// Get email from ID
	var userEmail string
	err = db.QueryRow(`SELECT email FROM users WHERE id = $1`, userID).Scan(&userEmail)
	if err != nil {
		logs.Err(
			db,
			"DB err",
			"Failed to query DB.",
			err,
			map[string]any{
				"payload": p,
			},
			userID,
		)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Check if emails are the same
	if email == userEmail {
		w.WriteHeader(http.StatusConflict)
		return
	}

	// Check if the email is already taken
	var exists bool
	err = db.QueryRow(`
		SELECT
		EXISTS (
		  SELECT 1 FROM users
		  WHERE LOWER(email) = LOWER($1) AND id <> $2
		)
		OR
		EXISTS (
			SELECT 1 FROM email_change_tokens
			WHERE LOWER(new_email) = LOWER($1)
			  AND (created_at + INTERVAL '1 day' >= NOW())
			  AND user_id <> $2
		)
		`, email, userID).Scan(&exists)
	if err != nil {
		logs.Err(
			db,
			"DB err",
			"Failed to query the DB.",
			err,
			map[string]any{
				"payload":       p,
				"current_email": userEmail,
				"new_email":     email,
			},
			userID,
		)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if exists {
		w.WriteHeader(http.StatusConflict)
		return
	}

	// Generate a token & hash it
	rawToken, err := gonanoid.New(128)
	if err != nil {
		logs.Err(
			db,
			"Token gen err",
			"Gonanoid failed to generate a token.",
			err,
			map[string]any{
				"payload": p,
			},
			userID,
		)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	tokenHash := users.HashToken(rawToken)

	// Store the token
	// Store/refresh the token (replace existing row for this user)
	_, err = db.Exec(`
		INSERT INTO email_change_tokens (user_id, token_hash, new_email)
		VALUES ($1, $2, $3)
		ON CONFLICT (user_id) DO UPDATE
		SET token_hash = EXCLUDED.token_hash,
			new_email  = EXCLUDED.new_email,
			created_at = NOW()
	`, userID, tokenHash, email)
	if err != nil {
		logs.Err(
			db,
			"DB err",
			"Failed to query the DB.",
			err,
			map[string]any{
				"payload": p,
			},
			userID,
		)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Send the email
	go func() {
		frontend := os.Getenv("FRONTEND_URL")
		u := fmt.Sprintf("%s/auth/change-email?token=%s", frontend, url.PathEscape(rawToken))
		err = email2.SendEmailChange(email, u)
		if err != nil {
			logs.Err(
				db,
				"SMTP err",
				"Failed to send mail",
				err,
				map[string]any{
					"route": r.URL.Path,
					"email": email,
				},
				userID,
			)
			return
		}
	}()

	w.WriteHeader(http.StatusNoContent)
}

func UpdateEmail(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	// Get token from URL param & hash it
	rawChangeToken := chi.URLParam(r, "token")
	changeTokenHash := users.HashToken(rawChangeToken)

	// Delete the email change token & get its new email
	var newEmail string
	var tokenCreatedAt time.Time
	var userID int64
	err := db.QueryRow(`
		DELETE FROM email_change_tokens
		WHERE token_hash = $1
		RETURNING new_email, created_at, user_id
		`, changeTokenHash).Scan(&newEmail, &tokenCreatedAt, &userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			w.WriteHeader(http.StatusNotFound)
		} else {
			logs.Err(
				db,
				"DB err",
				"Failed to query the DB.",
				err,
				map[string]any{
					"change_token_hash": changeTokenHash,
					"new_email":         newEmail,
				},
				userID,
			)
			w.WriteHeader(http.StatusInternalServerError)
		}
		return
	}

	// Check if the token is expired
	if time.Since(tokenCreatedAt) > 24*time.Hour {
		w.WriteHeader(http.StatusGone)
		return
	}

	// Check if the email is already taken
	var exists bool
	err = db.QueryRow(`SELECT EXISTS (SELECT 1 FROM users WHERE email = $1)`, newEmail).Scan(&exists)
	if err != nil {
		logs.Err(
			db,
			"DB err",
			"Failed to query the DB.",
			err,
			map[string]any{
				"change_token_hash": changeTokenHash,
				"new_email":         newEmail,
			},
			userID,
		)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if exists {
		w.WriteHeader(http.StatusConflict)
		return
	}

	// Update the user's email
	_, err = db.Exec(`UPDATE users SET email = $1 WHERE id = $2`, newEmail, userID)
	if err != nil {
		logs.Err(
			db,
			"DB err",
			"Failed to query the DB.",
			err,
			map[string]any{
				"change_token_hash": changeTokenHash,
				"new_email":         newEmail,
			},
			userID,
		)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
