package handlers

import (
	"github.com/immutability-io/reference-app/libhttp"
	"html/template"
	"net/http"
)

func GetHome(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")

	/*
		ciamDomain := os.Getenv("CIAM_DOMAIN")
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client := &http.Client{Transport: tr}
		sessionDetails, _ := http.NewRequest("GET", "https://"+ciamDomain+"/ui/api/session", nil)
		cookie, _ := r.Cookie("token")
		sessionDetails.AddCookie(cookie)
		resp, _ := client.Do(sessionDetails)
		var htmlData []byte
		if resp != nil {
			htmlData, _ = ioutil.ReadAll(resp.Body)
			logrus.Debug(string(htmlData))
		}
	*/
	tmpl, err := template.ParseFiles("templates/dashboard.html.tmpl", "templates/home.html.tmpl")
	if err != nil {
		libhttp.HandleErrorJson(w, err)
		return
	}

	tmpl.Execute(w, nil)
}
