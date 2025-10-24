package mw

import (
	"app/helpers/logs"
	"database/sql"
	"fmt"
	"net/http"
)

func RecoverAndLog(db *sql.DB) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					logs.Err(db, "panic", "unhandled panic in handler",
						fmt.Errorf("%v", rec),
						map[string]any{"method": r.Method, "path": r.URL.Path},
						"",
					)
					http.Error(w, http.StatusText(500), 500)
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}
