package handlers

import (
	email2 "app/helpers/email"
	"app/helpers/logs"
	"app/helpers/users"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/mail"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/alexedwards/argon2id"
	"github.com/go-chi/chi/v5"
	"github.com/matoous/go-nanoid/v2"
	"github.com/sony/sonyflake"
)

func RegistrationHandler(w http.ResponseWriter, r *http.Request, sf *sonyflake.Sonyflake, db *sql.DB) {
	// Payload
	type Payload struct {
		Name     string `json:"name"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	var p Payload

	// Decode payload
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	err := dec.Decode(&p)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Format email
	email := strings.TrimSpace(strings.ToLower(p.Email))
	_, err = mail.ParseAddress(email)
	if err != nil {
		w.WriteHeader(http.StatusUnprocessableEntity)
		return
	}

	// Validate
	if len(p.Name) > 64 || len(email) > 254 || len(p.Password) < 8 {
		w.WriteHeader(http.StatusUnprocessableEntity)
		return
	}

	// Hash the password
	hash, err := argon2id.CreateHash(p.Password, argon2id.DefaultParams)
	if err != nil {
		logs.Err(
			db,
			"Argon2id",
			"Failed to create password hash",
			err,
			map[string]any{
				"route": r.URL.Path,
				"email": strings.ToLower(strings.TrimSpace(p.Email)),
			},
			0,
		)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Generate ID
	id, err := sf.NextID()
	if err != nil {
		logs.Err(
			db,
			"Sonyflake ID gen",
			"Failed to generate sonyflake ID",
			err,
			map[string]any{
				"route": r.URL.Path,
				"email": email,
			},
			0,
		)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// (Attempt to) store the user
	res, err := db.Exec(`INSERT INTO users (id, name, email, password_hash)
	VALUES ($1, $2, $3, $4)
	ON CONFLICT (email) DO NOTHING`, id, p.Name, email, hash)
	if err != nil {
		logs.Err(
			db,
			"User creation",
			"Failed to insert the user into the database",
			err,
			map[string]any{
				"route": r.URL.Path,
				"email": email,
			},
			0,
		)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Check for email conflict
	rows, _ := res.RowsAffected()
	if rows == 0 {
		w.WriteHeader(http.StatusConflict)
		return
	}

	// Generate & hash verification token
	rawToken, err := gonanoid.New(128)
	if err != nil {
		logs.Err(
			db,
			"Gonanoid generation",
			"Gonanoid failed to generate the email verification token.",
			err,
			map[string]any{
				"route": r.URL.Path,
				"email": email,
			},
			0,
		)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	tokenHash := users.HashToken(rawToken)

	// Store the token
	_, err = db.Exec(`INSERT INTO verification_tokens (user_id, token_hash)
	VALUES ($1, $2)
	ON CONFLICT (user_id)
	DO UPDATE SET
  		token_hash = EXCLUDED.token_hash,
  		created_at = NOW()`, id, tokenHash)
	if err != nil {
		logs.Err(
			db,
			"Verification token storage",
			"Failed to store the verification token in the database.",
			err,
			map[string]any{
				"route": r.URL.Path,
				"email": email,
			},
			0,
		)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Send verification email
	frontend := os.Getenv("FRONTEND_URL")
	u := fmt.Sprintf("%s/auth/verify?token=%s", frontend, url.PathEscape(rawToken))
	err = email2.SendVerification(email, u)
	if err != nil {
		logs.Err(
			db,
			"Email sending error",
			"Failed to send the verification email",
			err,
			map[string]any{
				"route": r.URL.Path,
				"email": email,
			},
			int64(id),
		)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

func LoginHandler(w http.ResponseWriter, r *http.Request, sf *sonyflake.Sonyflake, db *sql.DB) {
	// Payload
	type Payload struct {
		Email    string `json:"email"`
		Password string `json:"password"`
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

	// Validate
	if len(p.Email) > 254 || len(p.Password) < 8 {
		w.WriteHeader(http.StatusUnprocessableEntity)
		return
	}

	// Format email
	email := strings.TrimSpace(strings.ToLower(p.Email))
	_, err = mail.ParseAddress(email)
	if err != nil {
		w.WriteHeader(http.StatusUnprocessableEntity)
		return
	}

	// Get the user's ID, password_hash and email_verified
	var userID int64
	var passwordHash string
	var verified bool
	err = db.QueryRow(`SELECT id, password_hash, email_verified FROM users WHERE email = $1`, email).
		Scan(&userID, &passwordHash, &verified)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			w.WriteHeader(http.StatusUnauthorized)
		} else {
			logs.Err(
				db,
				"User data select",
				"Failed to fetch the user's data from the db.",
				err,
				map[string]any{
					"route": r.URL.Path,
					"email": email,
				},
				userID,
			)
			w.WriteHeader(http.StatusInternalServerError)
		}
		return
	}

	// Check if password matches
	match, err := argon2id.ComparePasswordAndHash(p.Password, passwordHash)
	if err != nil {
		logs.Err(
			db,
			"Argon2id comparison",
			"Argon2id failed to compare the passwords",
			err,
			map[string]any{
				"route": r.URL.Path,
				"email": email,
			},
			userID,
		)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if !match {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// 403 if email not verified
	if !verified {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	// Login successful

	// Generate session token & hash it
	rawToken, err := gonanoid.New(128)
	if err != nil {
		logs.Err(
			db,
			"Session token generation error",
			"Gonanoid failed to generate the session token.",
			err,
			map[string]any{
				"route": r.URL.Path,
				"email": email,
			},
			userID,
		)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	tokenHash := users.HashToken(rawToken)

	// Generate ID
	idInt, err := sf.NextID()
	if err != nil {
		logs.Err(
			db,
			"Sonyflake ID gen",
			"Sonyflake failed to generate the session ID.",
			err,
			map[string]any{
				"route": r.URL.Path,
				"email": email,
			},
			userID,
		)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	id := strconv.FormatUint(idInt, 10)

	// Store the session
	_, err = db.Exec(`INSERT INTO sessions (id, user_id, token_hash)
	VALUES ($1, $2, $3)`, id, userID, tokenHash)
	if err != nil {
		logs.Err(
			db,
			"Session storage error",
			"Failed to store the session in the db",
			err,
			map[string]any{
				"route": r.URL.Path,
				"email": email,
			},
			userID,
		)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Return the unhashed token
	w.WriteHeader(http.StatusOK)
	if err = json.NewEncoder(w).Encode(map[string]interface{}{
		"token": rawToken,
	}); err != nil {
		logs.Err(
			db,
			"Token return fail",
			"Failed to return the token",
			err,
			map[string]any{
				"route": r.URL.Path,
				"email": email,
			},
			userID,
		)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func TokenCheckHandler(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	// Get token from auth header
	rawToken := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")

	// Hash the token & check if it exists
	token := users.HashToken(rawToken)

	var exists bool
	err := db.QueryRow(`SELECT EXISTS (SELECT 1 FROM sessions WHERE token_hash = $1)`, token).Scan(&exists)
	if err != nil {
		logs.Err(
			db,
			"DB err",
			"Failed to query the DB",
			err,
			map[string]any{
				"route": r.URL.Path,
			},
			0,
		)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if !exists {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func SendPasswordResetHandler(w http.ResponseWriter, r *http.Request, db *sql.DB) {
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

	// Format email
	email := strings.TrimSpace(strings.ToLower(p.Email))
	_, err = mail.ParseAddress(email)
	if err != nil {
		w.WriteHeader(http.StatusUnprocessableEntity)
		return
	}

	// Get user ID from email
	var userID int64
	err = db.QueryRow(`SELECT id FROM users WHERE email = $1`, email).Scan(&userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			w.WriteHeader(http.StatusNoContent) // Fake 204 if the user doesn't exist
		} else {
			logs.Err(
				db,
				"DB err",
				"Failed to query the DB",
				err,
				map[string]any{
					"route": r.URL.Path,
					"email": email,
				},
				userID,
			)
			w.WriteHeader(http.StatusInternalServerError)
		}
		return
	}

	// Check existing token timestamp
	var lastSent time.Time
	err = db.QueryRow(`
		SELECT created_at
		FROM reset_tokens
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
				"route": r.URL.Path,
				"email": email,
			},
			userID,
		)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Generate a reset token & hash it
	rawToken, err := gonanoid.New(128)
	if err != nil {
		logs.Err(
			db,
			"Gonanoid err",
			"Gonanoid failed to generate the token",
			err,
			map[string]any{
				"route": r.URL.Path,
				"email": email,
			},
			userID,
		)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	tokenHash := users.HashToken(rawToken)

	// Store the token
	_, err = db.Exec(`
		INSERT INTO reset_tokens (user_id, token_hash)
		VALUES ($1, $2)
		ON CONFLICT (user_id)
		DO UPDATE SET token_hash = EXCLUDED.token_hash, created_at = NOW()
		`, userID, tokenHash)
	if err != nil {
		logs.Err(
			db,
			"DB err",
			"Failed to store the token in the DB",
			err,
			map[string]any{
				"route": r.URL.Path,
				"email": email,
			},
			userID,
		)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Send reset email
	go func() {
		frontend := os.Getenv("FRONTEND_URL")
		u := fmt.Sprintf("%s/auth/reset?token=%s", frontend, url.PathEscape(rawToken))
		err := email2.SendReset(email, u)
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

func PasswordResetHandler(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	// Get token from URL & hash it
	rawToken := chi.URLParam(r, "token")
	tokenHash := users.HashToken(rawToken)

	// Payload
	type Payload struct {
		Password string `json:"password"`
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

	// Validate
	if len(p.Password) < 8 {
		w.WriteHeader(http.StatusUnprocessableEntity)
		return
	}

	// Get user ID from token
	var userID int64
	err = db.QueryRow(`
		SELECT user_id
		FROM reset_tokens
		WHERE token_hash = $1
		AND created_at >= NOW() - INTERVAL '1 day'
		`, tokenHash).Scan(&userID)
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

	// Hash the new password
	hash, err := argon2id.CreateHash(p.Password, argon2id.DefaultParams)
	if err != nil {
		logs.Err(
			db,
			"Argon2id err",
			"Argon2id failed to create hash",
			err,
			map[string]any{
				"route": r.URL.Path,
			},
			userID,
		)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Update the user's password
	_, err = db.Exec(`
		UPDATE users
		SET password_hash = $1
		WHERE id = $2`, hash, userID)
	if err != nil {
		logs.Err(
			db,
			"DB err",
			"Failed to update the user",
			err,
			map[string]any{
				"route": r.URL.Path,
			},
			userID,
		)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Delete the reset token
	_, err = db.Exec(`DELETE FROM reset_tokens WHERE user_id = $1`, userID)
	if err != nil {
		logs.Err(
			db,
			"DB err",
			"Failed to delete reset token from DB",
			err,
			map[string]any{
				"route": r.URL.Path,
			},
			userID,
		)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Delete all the user's sessions
	_, err = db.Exec(`DELETE FROM sessions WHERE user_id = $1`, userID)
	if err != nil {
		logs.Err(
			db,
			"DB err",
			"Failed to delete all sessions from DB",
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

func PasswordChangeHandler(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	// Get token
	rawToken := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")

	// Get user ID from token
	userID, err := users.GetId(rawToken, w, db)
	if err != nil {
		return
	}

	// Payload
	type Payload struct {
		Password    string `json:"password"`
		NewPassword string `json:"new_password"`
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
	defer func() {
		_ = r.Body.Close()
	}()

	// Validate
	if len(p.Password) < 8 || len(p.NewPassword) < 8 {
		w.WriteHeader(http.StatusUnprocessableEntity)
		return
	}

	// Get the user's current password
	var currentHash string
	err = db.QueryRow(`SELECT password_hash FROM users WHERE id = $1`, userID).Scan(&currentHash)
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

	// Check if the password matches
	match, err := argon2id.ComparePasswordAndHash(p.Password, currentHash)
	if err != nil {
		log.Println(err)
		logs.Err(
			db,
			"Argon2id err",
			"Argon2id failed to compare password",
			err,
			map[string]any{
				"route": r.URL.Path,
			},
			userID,
		)
		return
	}

	if !match {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Hash the new password
	hash, err := argon2id.CreateHash(p.NewPassword, argon2id.DefaultParams)
	if err != nil {
		logs.Err(
			db,
			"Argon2id err",
			"Argon2id failed to create hash",
			err,
			map[string]any{
				"route": r.URL.Path,
			},
			userID,
		)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Update the user
	_, err = db.Exec(`UPDATE users SET password_hash = $1 WHERE id = $2`, hash, userID)
	if err != nil {
		logs.Err(
			db,
			"DB err",
			"Failed to update the user",
			err,
			map[string]any{
				"route": r.URL.Path,
			},
			userID,
		)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Delete all sessions
	_, err = db.Exec(`DELETE FROM sessions WHERE user_id = $1`, userID)
	if err != nil {
		logs.Err(
			db,
			"DB err",
			"Failed to delete sessions",
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

func LogoutHandler(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	// Get token
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if token == "" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Hash the token
	tokenHash := users.HashToken(token)

	// Delete from DB
	_, err := db.Exec(`DELETE FROM sessions WHERE token_hash = $1`, tokenHash)
	if err != nil {
		logs.Err(
			db,
			"DB err",
			"Failed to query the DB.",
			err,
			map[string]any{
				"token": tokenHash,
				"stage": "db_delete",
			},
			0,
		)
	}

	w.WriteHeader(http.StatusNoContent)
}
