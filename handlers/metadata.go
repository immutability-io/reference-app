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
	IAMInfo          ec2metadata.EC2IAMInfo
	Signature        string
	PKCS7            string
}

func GetIdentityDocument(config *viper.Viper) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		var session libhttp.CIAMSession
		session, err := libhttp.GetCIAMSession(config, r)
		ec2metadataSvc := ec2metadata.New(aws.New())

		signature, err := ec2metadataSvc.GetDynamicData("instance-identity/signature")
		if err != nil {
			logrus.Debug(err)
		}
		pkcs7, err := ec2metadataSvc.GetDynamicData("instance-identity/pkcs7")
		if err != nil {
			logrus.Debug(err)
		}

		var identityDocument ec2metadata.EC2InstanceIdentityDocument
		identityDocument, err = ec2metadataSvc.GetInstanceIdentityDocument()
		if err != nil {
			logrus.Debug(err)
		}

		var iamInfo ec2metadata.EC2IAMInfo
		iamInfo, err = ec2metadataSvc.IAMInfo()
		if err != nil {
			logrus.Debug(err)
		}
		data := MetaData{
			Session:          session,
			InstanceDocument: identityDocument,
			IAMInfo:          iamInfo,
			Signature:        signature,
			PKCS7:            pkcs7,
		}

		tmpl, err := template.ParseFiles("/content/templates/index.html.tmpl", "/content/templates/metadata.html.tmpl")

		if err != nil {
			libhttp.HandleErrorJSON(w, err)
			return
		}

		tmpl.Execute(w, data)
	}
}
