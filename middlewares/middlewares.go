// Package middlewares provides common middleware handlers.
package middlewares

import (
	"crypto/tls"
	"github.com/gorilla/context"
	"github.com/gorilla/sessions"
	"net/http"
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

		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client := &http.Client{Transport: tr}
		sessionRequest, _ := http.NewRequest("GET", "https://orchis.ciam-d.troweprice.io/ui/api/session/verify", nil)
		cookie, _ := req.Cookie("token")
		if cookie == nil {
			http.Redirect(res, req, "https://orchis.ciam-d.troweprice.io", 302)
			return
		}
		sessionRequest.AddCookie(cookie)
		resp, _ := client.Do(sessionRequest)

		if resp == nil || resp.StatusCode != 200 {
			http.Redirect(res, req, "https://orchis.ciam-d.troweprice.io", 302)
			return
		}
		next.ServeHTTP(res, req)
	})
}
