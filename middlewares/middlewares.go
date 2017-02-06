// Package middlewares provides common middleware handlers.
package middlewares

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"net/http"
	"strconv"

	"github.com/Sirupsen/logrus"
	"github.com/gorilla/context"
	"github.com/gorilla/sessions"
	"github.com/spf13/viper"
)

// SetSessionStore sets the session store
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
		caCertFile := config.Get("http_cacert_file").(string)
		caCert, err := ioutil.ReadFile(caCertFile)
		logrus.Debug("http_cacert_file: " + caCertFile)
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
		sessionVerifyURL := config.Get("ciam_session_verify_url").(string)
		logrus.Debug("ciam_session_verify_url: " + sessionVerifyURL)
		sessionRedirectURL := config.Get("ciam_authentication_redirect_url").(string)
		logrus.Debug("ciam_authentication_redirect_url: " + sessionRedirectURL)
		sessionRequest, _ := http.NewRequest("GET", sessionVerifyURL, nil)
		ciamCookieName := config.Get("ciam-cookie-name").(string)
		cookie, _ := req.Cookie(ciamCookieName)
		if cookie == nil {
			logrus.Debug("No cookie: " + ciamCookieName)
			http.Redirect(res, req, sessionRedirectURL, 302)
			return
		}
		logrus.Debug("Cookie: " + cookie.String())
		sessionRequest.AddCookie(cookie)
		resp, _ := client.Do(sessionRequest)

		if resp == nil {
			logrus.Debug("curl -v --cookie \"" + cookie.String() + "\" " + sessionVerifyURL)
			http.Redirect(res, req, sessionRedirectURL, 302)
			return
		}
		if resp.StatusCode != 200 {
			logrus.Debug("No session - bad status " + strconv.Itoa(resp.StatusCode))
			var htmlData []byte
			htmlData, _ = ioutil.ReadAll(resp.Body)
			message := string(htmlData[:])
			logrus.Debug("Response " + message)
			http.Redirect(res, req, sessionRedirectURL, 302)
			return
		}
		logrus.Debug("Session verified")
		next.ServeHTTP(res, req)
	})
}
