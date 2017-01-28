// Package libhttp provides http related library functions.
package libhttp

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/Sirupsen/logrus"
	"github.com/spf13/viper"
	"io/ioutil"
	"net/http"
	"strings"
)

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

func VaultTLSAuthenticate(config *viper.Viper) (token string, err error) {
	vaultCaCertFile := config.Get("vault_cacert_file").(string)
	caCert, err := ioutil.ReadFile(vaultCaCertFile)
	if err != nil {
		logrus.Fatal(err)
		return
	}
	certFile := config.Get("vault_cert_file").(string)
	keyFile := config.Get("vault_key_file").(string)
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		logrus.Fatal(err)
		return "", err
	}
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
				RootCAs:      caCertPool,
			},
		},
	}
	vaultCertAuthUrl := config.Get("vault_cert_auth_url").(string)
	authRequest, _ := http.NewRequest("POST", vaultCertAuthUrl, nil)
	resp, err := client.Do(authRequest)
	if err != nil {
		logrus.Fatal(err)
		return "", err
	}
	var authenticationData AuthenticationResponse
	var htmlData []byte
	if resp != nil {
		htmlData, _ = ioutil.ReadAll(resp.Body)
	}
	if err != nil {
		logrus.Fatal(err)
		return "", err
	}
	err = json.Unmarshal(htmlData, &authenticationData)
	if err != nil {
		logrus.Fatal(err)
		return "", err
	}
	return authenticationData.Auth.ClientToken, nil
}

// BasicRealm is used when setting the WWW-Authenticate response header.
var BasicRealm = "Authorization Required"

// ParseBasicAuth parses an HTTP Basic Authentication string.
// "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==" returns ("Aladdin", "open sesame", true).
func ParseBasicAuth(auth string) (username, password string, ok bool) {
	if !strings.HasPrefix(auth, "Basic ") {
		return
	}
	c, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "Basic "))
	if err != nil {
		return
	}
	cs := string(c)
	s := strings.IndexByte(cs, ':')
	if s < 0 {
		return
	}
	return cs[:s], cs[s+1:], true
}

// BasicAuthUnauthorized denies authentication.
func BasicAuthUnauthorized(w http.ResponseWriter, err error) {
	message := "Not Authorized."

	if err != nil {
		message += fmt.Sprintf(" Error: %v", err)
	}

	w.Header().Set("WWW-Authenticate", "Basic realm=\""+BasicRealm+"\"")
	http.Error(w, message, http.StatusUnauthorized)
}

// HandleErrorJson wraps error in JSON structure.
func HandleErrorJson(w http.ResponseWriter, err error) {
	var errMap map[string]string

	if err == nil {
		errMap = map[string]string{"Error": "Error struct is nil."}
	} else {
		errMap = map[string]string{"Error": err.Error()}
	}

	errJson, _ := json.Marshal(errMap)
	http.Error(w, string(errJson), http.StatusInternalServerError)
}
