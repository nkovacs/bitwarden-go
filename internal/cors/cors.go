package cors

import (
	"net/http"
	"strings"
)

type Cors struct {
	allowedOrigins map[string]bool
}

func New() Cors {
	return Cors{
		allowedOrigins: nil,
	}
}

func NewOrigins(allowed ...string) Cors {
	m := make(map[string]bool)
	for _, origin := range allowed {
		m[origin] = true
	}
	return Cors{
		allowedOrigins: m,
	}
}

func (c Cors) handle(w http.ResponseWriter, r *http.Request) bool {
	allowed := false
	if c.allowedOrigins == nil {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		allowed = true
	} else if origin := r.Header.Get("Origin"); origin != "" && c.allowedOrigins[origin] {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Vary", "Origin")
		allowed = true
	}

	if allowed {
		// handle Access-Control-Request-Headers
		requestHeaders, ok := r.Header["Access-Control-Request-Headers"]
		if ok {
			// all headers are safe for CORS
			w.Header().Set("Access-Control-Allow-Headers", strings.Join(requestHeaders, ", "))
		}
	}

	return allowed
}

var methods = []string{"GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"}

func (c Cors) MiddleWare(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		allowed := c.handle(w, r)
		if r.Method == "OPTIONS" {
			if allowed {
				for _, m := range methods {
					w.Header().Add("Access-Control-Allow-Methods", m)
				}
			}
			w.WriteHeader(http.StatusOK)
		} else {
			next.ServeHTTP(w, r)
		}
	})
}
