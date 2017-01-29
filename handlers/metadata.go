package handlers

import (
	"github.com/Sirupsen/logrus"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/immutability-io/reference-app/libhttp"
	"github.com/spf13/viper"
	"html/template"
	"net/http"
)

func GetIdentityDocument(config *viper.Viper) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		ec2metadataSvc := ec2metadata.New(session.New())

		var identityDocument ec2metadata.EC2InstanceIdentityDocument
		identityDocument, err := ec2metadataSvc.GetInstanceIdentityDocument()
		if err != nil {
			logrus.Debug(err)
		}

		tmpl, err := template.ParseFiles("/content/templates/dashboard.html.tmpl", "/content/templates/metadata.html.tmpl")

		if err != nil {
			libhttp.HandleErrorJson(w, err)
			return
		}

		tmpl.Execute(w, identityDocument)
	}
}
