package handlers

import (
	"html/template"
	"net/http"

	"github.com/immutability-io/reference-app/libhttp"
	"github.com/spf13/viper"
)

type SecretData struct {
	Session libhttp.CIAMSession
	Secret  libhttp.CustomSecret
}

func GetSecret(config *viper.Viper) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		var session libhttp.CIAMSession
		session, err := libhttp.GetCIAMSession(config, r)
		customSecret, err := libhttp.GetCustomSecret(config)

		if err != nil {
			libhttp.HandleErrorJSON(w, err)
			return
		}

		data := SecretData{
			Session: session,
			Secret:  customSecret,
		}

		tmpl, err := template.ParseFiles("/content/templates/index.html.tmpl", "/content/templates/secret.html.tmpl")

		if err != nil {
			libhttp.HandleErrorJSON(w, err)
			return
		}

		tmpl.Execute(w, data)
	}
}
