package mw

import "net/http"

// MaxBody - Caps the body size limit before a handler is hit
func MaxBody(n int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodPost, http.MethodPut, http.MethodPatch:
				if r.ContentLength > n && r.ContentLength != -1 {
					w.WriteHeader(http.StatusRequestEntityTooLarge) // 413
					return
				}
				r.Body = http.MaxBytesReader(w, r.Body, n)
			}
			next.ServeHTTP(w, r)
		})
	}
}
