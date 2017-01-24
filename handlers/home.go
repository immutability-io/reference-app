package handlers

import (
	"crypto/tls"
	"encoding/json"
	"github.com/immutability-io/reference-app/libhttp"
	"html/template"
	"io/ioutil"
	"net/http"
	"os"
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

func GetHome(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	ciamDomain := os.Getenv("CIAM_DOMAIN")
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	sessionDetails, _ := http.NewRequest("GET", "https://"+ciamDomain+"/ui/api/session", nil)
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

	tmpl, err := template.ParseFiles("templates/dashboard.html.tmpl", "templates/home.html.tmpl")

	if err != nil {
		libhttp.HandleErrorJson(w, err)
		return
	}

	tmpl.Execute(w, data)
}
