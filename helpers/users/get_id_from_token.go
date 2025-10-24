package users

import (
	"crypto/sha256"
	"database/sql"
	"errors"
	"net/http"
)

// HashToken - Hashes the token using SHA256
func HashToken(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

// GetId - Gets the user's ID by their session token
func GetId(rawToken string, w http.ResponseWriter, db *sql.DB) (int64, error) {
	token := HashToken(rawToken)

	var userID int64
	err := db.QueryRow(`
		UPDATE sessions
		SET last_used_at = NOW()
		WHERE token_hash = $1
		  AND last_used_at >= NOW() - INTERVAL '1 week'
		RETURNING user_id
	`, token).Scan(&userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			w.WriteHeader(http.StatusUnauthorized)
			return 0, err
		}
		w.WriteHeader(http.StatusInternalServerError)
		return 0, err
	}

	return userID, nil
}
