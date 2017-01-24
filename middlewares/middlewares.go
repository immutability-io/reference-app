// Package middlewares provides common middleware handlers.
package middlewares

import (
	"crypto/tls"
	"github.com/gorilla/context"
	"github.com/gorilla/sessions"
	"net/http"
	"os"
)

func SetSessionStore(sessionStore sessions.Store) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
			context.Set(req, "sessionStore", sessionStore)

			next.ServeHTTP(res, req)
		})
	}
}

// MustLogin is a middleware that checks existence of current user.
func MustLogin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		ciamDomain := os.Getenv("CIAM_DOMAIN")
		if ciamDomain == "" {
			return
		}
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client := &http.Client{Transport: tr}
		sessionRequest, _ := http.NewRequest("GET", "https://"+ciamDomain+"/ui/api/session/verify", nil)
		cookie, _ := req.Cookie("token")
		if cookie == nil {
			http.Redirect(res, req, "https://"+ciamDomain, 302)
			return
		}
		sessionRequest.AddCookie(cookie)
		resp, _ := client.Do(sessionRequest)

		if resp == nil || resp.StatusCode != 200 {
			http.Redirect(res, req, "https://"+ciamDomain, 302)
			return
		}
		next.ServeHTTP(res, req)
	})
}
