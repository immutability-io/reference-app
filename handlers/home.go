package handlers

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"github.com/Sirupsen/logrus"
	"github.com/immutability-io/reference-app/libhttp"
	"html/template"
	"io/ioutil"
	"net/http"
)

type CIAMSession struct {
	Entitlements             []string `json:"entitlements"`
	LastName                 string   `json:"lastName"`
	GoogleAuthSecretAccepted string   `json:"googleAuthSecretAccepted"`
	CustomerAlias            string   `json:"customerAlias"`
	MfaMethod                string   `json:"mfaMethod"`
	Locale                   string   `json:"locale"`
	EulaApproval             string   `json:"eulaApproval"`
	Uuid                     string   `json:"uuid"`
	FirstName                string   `json:"firstName"`
	Uid                      string   `json:"uid"`
	KbaAccepted              string   `json:"kbaAccepted"`
	EntitlementGroups        []string `json:"entitlementGroups"`
	AuthLevel                int      `json:"authLevel"`
	Customer                 string   `json:"customer"`
}

type CustomSecret struct {
	RequestId     string `json:"request_id"`
	LeaseId       string `json:"lease_id"`
	Renewable     bool   `json:"renewable"`
	LeaseDuration int    `json:"lease_duration"`
	Data          struct {
		Value struct {
			Secret1 string `json:"secret1"`
			Secret2 string `json:"secret2"`
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
}

type AuthenticationResponse struct {
	RequestId     string `json:"request_id"`
	LeaseId       string `json:"lease_id"`
	Renewable     bool   `json:"renewable"`
	LeaseDuration int    `json:"lease_duration"`
	Data          string `json:"data"`
	WrapInfo      string `json:"wrap_info"`
	Warnings      string `json:"warnings"`
	Auth          struct {
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

func GetHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	tmpl, err := template.ParseFiles("/content/templates/dashboard.html.tmpl", "/content/templates/health.html.tmpl")

	if err != nil {
		libhttp.HandleErrorJson(w, err)
		return
	}

	tmpl.Execute(w, nil)
}

func GetSecret(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	caCert, err := ioutil.ReadFile("/etc/ssl/cacert.crt")
	if err != nil {
		logrus.Fatal(err)
		return
	}
	certFile := "/etc/ssl/application.crt"
	keyFile := "/etc/ssl/application.key"
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		logrus.Fatal(err)
	}
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
				RootCAs:      caCertPool,
			},
		},
	}
	authRequest, _ := http.NewRequest("POST", "https://vault.troweprice.com:8200/v1/auth/cert/login", nil)
	resp, err := client.Do(authRequest)
	if err != nil {
		libhttp.HandleErrorJson(w, err)
		return
	}
	var data AuthenticationResponse
	var htmlData []byte
	if resp != nil {
		htmlData, _ = ioutil.ReadAll(resp.Body)
	}
	if err != nil {
		panic(err.Error())
	}
	err = json.Unmarshal(htmlData, &data)
	if err != nil {
		libhttp.HandleErrorJson(w, err)
		return
	}

	tmpl, err := template.ParseFiles("/content/templates/dashboard.html.tmpl", "/content/templates/secret.html.tmpl")

	if err != nil {
		libhttp.HandleErrorJson(w, err)
		return
	}

	tmpl.Execute(w, data)

}

func GetHome(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	caCert, err := ioutil.ReadFile("/etc/ssl/root.crt")
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
	sessionDetails, _ := http.NewRequest("GET", "https://orchis.ciam-d.troweprice.io/ui/api/session", nil)
	cookie, _ := r.Cookie("token")
	sessionDetails.AddCookie(cookie)
	resp, err := client.Do(sessionDetails)
	if err != nil {
		libhttp.HandleErrorJson(w, err)
		return
	}
	var data CIAMSession
	var htmlData []byte
	if resp != nil {
		htmlData, _ = ioutil.ReadAll(resp.Body)
	}
	if err != nil {
		panic(err.Error())
	}
	err = json.Unmarshal(htmlData, &data)
	if err != nil {
		libhttp.HandleErrorJson(w, err)
		return
	}

	tmpl, err := template.ParseFiles("/content/templates/dashboard.html.tmpl", "/content/templates/home.html.tmpl")

	if err != nil {
		libhttp.HandleErrorJson(w, err)
		return
	}

	tmpl.Execute(w, data)
}
