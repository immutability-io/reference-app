// Package middlewares provides common middleware handlers.
package middlewares

import (
	"crypto/tls"
	"crypto/x509"
	"github.com/Sirupsen/logrus"
	"github.com/gorilla/context"
	"github.com/gorilla/sessions"
	"github.com/spf13/viper"
	"io/ioutil"
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
func MustLogin(config *viper.Viper, next http.Handler) http.Handler {
	return http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		caCertFile := config.Get("vault_cacert_file").(string)
		caCert, err := ioutil.ReadFile(caCertFile)
		if err != nil {
			logrus.Fatal(err)
			return
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)

		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs: caCertPool,
				},
			},
		}
		sessionVerifyUrl := config.Get("ciam_session_verify_url").(string)
		sessionRedirectUrl := config.Get("ciam_authentication_redirect_url").(string)
		sessionRequest, _ := http.NewRequest("GET", sessionVerifyUrl, nil)
		cookie, _ := req.Cookie("token")
		if cookie == nil {
			http.Redirect(res, req, sessionRedirectUrl, 302)
			return
		}
		sessionRequest.AddCookie(cookie)
		resp, _ := client.Do(sessionRequest)

		if resp == nil || resp.StatusCode != 200 {
			http.Redirect(res, req, sessionRedirectUrl, 302)
			return
		}
		next.ServeHTTP(res, req)
	})
}
