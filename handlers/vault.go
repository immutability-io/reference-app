package handlers

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"github.com/Sirupsen/logrus"
	"github.com/immutability-io/reference-app/libhttp"
	"github.com/spf13/viper"
	"html/template"
	"io/ioutil"
	"net/http"
)

type CustomSecret struct {
	Secret1 string `json:"secret1"`
	Secret2 string `json:"secret2"`
}

type VaultSecret struct {
	RequestId     string `json:"request_id"`
	LeaseId       string `json:"lease_id"`
	Renewable     bool   `json:"renewable"`
	LeaseDuration int    `json:"lease_duration"`
	Data          struct {
		Value string `json:"value"`
	}
	WrapInfo string `json:"wrap_info"`
	Warnings string `json:"warnings"`
	Auth     struct {
		ClientToken string   `json:"client_token"`
		Accessor    string   `json:"accessor"`
		Policies    []string `json:"policies"`
		Meatdata    struct {
			AuthorityKeyId string `json:"authority_key_id"`
			CertName       string `json:"cert_name"`
			CommonName     string `json:"common_name"`
			SubjectKeyId   string `json:"subject_key_id"`
		}
		LeaseDuration int  `json:"lease_duration"`
		Renewable     bool `json:"renewable"`
	}
}

type SecretData struct {
	Session libhttp.CIAMSession
	Secret  CustomSecret
}

func GetSecret(config *viper.Viper) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		var session libhttp.CIAMSession
		session, err := libhttp.GetCIAMSession(config, r)
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
		token, err := libhttp.VaultTLSAuthenticate(config)
		if err != nil {
			libhttp.HandleErrorJson(w, err)
			return
		}
		secretUrl := config.Get("vault_secret_path").(string) + config.Get("application_id").(string)
		secretRequest, _ := http.NewRequest("GET", secretUrl, nil)
		secretRequest.Header.Set("X-Vault-Token", token)
		resp, err := client.Do(secretRequest)
		if err != nil {
			libhttp.HandleErrorJson(w, err)
			return
		}
		var htmlData []byte
		var vaultSecret VaultSecret
		if resp != nil {
			htmlData, _ = ioutil.ReadAll(resp.Body)
		}
		if err != nil {
			panic(err.Error())
		}
		err = json.Unmarshal(htmlData, &vaultSecret)
		if err != nil {
			libhttp.HandleErrorJson(w, err)
			return
		}

		var customSecret CustomSecret
		bytes := []byte(vaultSecret.Data.Value)
		err = json.Unmarshal(bytes, &customSecret)
		if err != nil {
			libhttp.HandleErrorJson(w, err)
			return
		}
		data := SecretData{
			Session: session,
			Secret:  customSecret,
		}

		tmpl, err := template.ParseFiles("/content/templates/index.html.tmpl", "/content/templates/secret.html.tmpl")

		if err != nil {
			libhttp.HandleErrorJson(w, err)
			return
		}

		tmpl.Execute(w, data)
	}
}
