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

func GetHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	tmpl, err := template.ParseFiles("/content/templates/dashboard.html.tmpl", "/content/templates/health.html.tmpl")

	if err != nil {
		libhttp.HandleErrorJson(w, err)
		return
	}

	tmpl.Execute(w, nil)
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
