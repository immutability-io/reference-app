package handlers

import (
	"github.com/immutability-io/reference-app/libhttp"
	"github.com/spf13/viper"
	"html/template"
	"net/http"
)

type HomeData struct {
	Session libhttp.CIAMSession
}

func GetHome(config *viper.Viper) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		var session libhttp.CIAMSession
		session, err := libhttp.GetCIAMSession(config, r)

		if err != nil {
			libhttp.HandleErrorJSON(w, err)
			return
		}
		data := HomeData{
			Session: session,
		}
		tmpl, err := template.ParseFiles("/content/templates/index.html.tmpl", "/content/templates/home.html.tmpl")

		if err != nil {
			libhttp.HandleErrorJSON(w, err)
			return
		}

		tmpl.Execute(w, data)
	}
}

func Logout(config *viper.Viper) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		err := libhttp.DeleteCIAMSession(config, r)

		if err != nil {
			libhttp.HandleErrorJSON(w, err)
			return
		}
		sessionRedirectUrl := config.Get("ciam_authentication_redirect_url").(string)
		http.Redirect(w, r, sessionRedirectUrl, 302)
	}
}
