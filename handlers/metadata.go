package handlers

import (
	"github.com/Sirupsen/logrus"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	aws "github.com/aws/aws-sdk-go/aws/session"
	"github.com/immutability-io/reference-app/libhttp"
	"github.com/spf13/viper"
	"html/template"
	"net/http"
)

type MetaData struct {
	Session          libhttp.CIAMSession
	InstanceDocument ec2metadata.EC2InstanceIdentityDocument
}

func GetIdentityDocument(config *viper.Viper) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		var session libhttp.CIAMSession
		session, err := libhttp.GetCIAMSession(config, r)
		ec2metadataSvc := ec2metadata.New(aws.New())

		var identityDocument ec2metadata.EC2InstanceIdentityDocument
		identityDocument, err = ec2metadataSvc.GetInstanceIdentityDocument()
		if err != nil {
			logrus.Debug(err)
		}
		data := MetaData{
			Session:          session,
			InstanceDocument: identityDocument,
		}

		tmpl, err := template.ParseFiles("/content/templates/index.html.tmpl", "/content/templates/metadata.html.tmpl")

		if err != nil {
			libhttp.HandleErrorJson(w, err)
			return
		}

		tmpl.Execute(w, data)
	}
}
