// Package libhttp provides http related library functions.
package libhttp

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/spf13/viper"
)

// CIAMSession is the CIAM Session
type CIAMSession struct {
	Entitlements             []string `json:"entitlements"`
	LastName                 string   `json:"lastName"`
	GoogleAuthSecretAccepted string   `json:"googleAuthSecretAccepted"`
	CustomerAlias            string   `json:"customerAlias"`
	MfaMethod                string   `json:"mfaMethod"`
	Locale                   string   `json:"locale"`
	EulaApproval             string   `json:"eulaApproval"`
	UUID                     string   `json:"uuid"`
	FirstName                string   `json:"firstName"`
	UID                      string   `json:"uid"`
	KbaAccepted              string   `json:"kbaAccepted"`
	EntitlementGroups        []string `json:"entitlementGroups"`
	AuthLevel                int      `json:"authLevel"`
	Customer                 string   `json:"customer"`
}

// AuthenticationResponse is returned on successful authentication from vault.
type AuthenticationResponse struct {
	RequestID     string `json:"request_id"`
	LeaseID       string `json:"lease_id"`
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
			AuthorityKeyID string `json:"authority_key_id"`
			CertName       string `json:"cert_name"`
			CommonName     string `json:"common_name"`
			SubjectKeyID   string `json:"subject_key_id"`
		}
		LeaseDuration int  `json:"lease_duration"`
		Renewable     bool `json:"renewable"`
	}
}

// CustomSecret is the application specific secret
type CustomSecret struct {
	Secret1 string `json:"secret1"`
	Secret2 string `json:"secret2"`
}

// VaultSecret is the response when you read a generic secert
type VaultSecret struct {
	RequestID     string `json:"request_id"`
	LeaseID       string `json:"lease_id"`
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
			AuthorityKeyID string `json:"authority_key_id"`
			CertName       string `json:"cert_name"`
			CommonName     string `json:"common_name"`
			SubjectKeyID   string `json:"subject_key_id"`
		}
		LeaseDuration int  `json:"lease_duration"`
		Renewable     bool `json:"renewable"`
	}
}

// VaultTLSAuthenticate is how you use TLS tokens to authenticate to vault
func VaultTLSAuthenticate(config *viper.Viper) (token string, err error) {
	vaultCaCertFile := config.Get("vault_cacert_file").(string)
	caCert, err := ioutil.ReadFile(vaultCaCertFile)
	if err != nil {
		logrus.Fatal(err)
		return "", err
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
	vaultCertAuthURL := config.Get("vault_cert_auth_url").(string)
	authRequest, _ := http.NewRequest("POST", vaultCertAuthURL, nil)
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

// VaultAppRoleAuthenticate is how you use vault AppRole to authenticate
func VaultAppRoleAuthenticate(config *viper.Viper) (token string, err error) {
	vaultCaCertFile := config.Get("vault_cacert_file").(string)
	caCert, err := ioutil.ReadFile(vaultCaCertFile)
	if err != nil {
		logrus.Fatal(err)
		return "", err
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
	vaultCertAuthURL := config.Get("vault_approle_auth_url").(string)
	secretID := config.Get("vault_secret_id").(string)
	roleID := config.Get("vault_role_id").(string)
	var jsonStr = []byte(`{"role_id":` + roleID + `,"secret_id":` + secretID + `}`)
	authRequest, _ := http.NewRequest("POST", vaultCertAuthURL, bytes.NewBuffer(jsonStr))
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

// GetCIAMSession returns the authenticated session
func GetCIAMSession(config *viper.Viper, r *http.Request) (session CIAMSession, err error) {
	var data CIAMSession
	caCertFile := config.Get("http_cacert_file").(string)
	logrus.Debug("CA Cert file: " + caCertFile)
	caCert, err := ioutil.ReadFile(caCertFile)
	if err != nil {
		logrus.Fatal(err)
		return data, err
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	client := &http.Client{
		Timeout: time.Second * 10,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: caCertPool,
			},
		},
	}
	ciamSessionURL := config.Get("ciam_session_url").(string)
	sessionDetails, _ := http.NewRequest("GET", ciamSessionURL, nil)
	ciamCookieName := config.Get("ciam-cookie-name").(string)
	cookie, _ := r.Cookie(ciamCookieName)
	sessionDetails.AddCookie(cookie)
	resp, err := client.Do(sessionDetails)
	logrus.Debug("ciam_session_url: " + ciamSessionURL)
	if err != nil {
		logrus.Debug("Error retrieving session")
		logrus.Fatal(err)
		return data, err
	}
	var htmlData []byte
	if resp != nil {
		htmlData, _ = ioutil.ReadAll(resp.Body)
	}
	if err != nil {
		logrus.Debug("Error parsing session")
		logrus.Fatal(err)
		panic(err.Error())
	}
	err = json.Unmarshal(htmlData, &data)
	if err != nil {
		logrus.Debug("Error marshalling session")
		logrus.Fatal(err)
		return data, err
	}
	return data, nil
}

// DeleteCIAMSession will log you out
func DeleteCIAMSession(config *viper.Viper, r *http.Request) (err error) {
	caCertFile := config.Get("http_cacert_file").(string)
	logrus.Debug("CA Cert file: " + caCertFile)
	caCert, err := ioutil.ReadFile(caCertFile)
	if err != nil {
		logrus.Fatal(err)
		return err
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
	ciamSessionURL := config.Get("ciam_session_url").(string)
	sessionDetails, _ := http.NewRequest("DELETE", ciamSessionURL, nil)
	ciamCookieName := config.Get("ciam-cookie-name").(string)
	cookie, _ := r.Cookie(ciamCookieName)
	sessionDetails.AddCookie(cookie)
	_, err = client.Do(sessionDetails)
	logrus.Debug("ciam_session_url: " + ciamSessionURL)
	return err
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

// HandleErrorJSON wraps error in JSON structure.
func HandleErrorJSON(w http.ResponseWriter, err error) {
	var errMap map[string]string

	if err == nil {
		errMap = map[string]string{"Error": "Error struct is nil."}
	} else {
		errMap = map[string]string{"Error": err.Error()}
	}

	errJSON, _ := json.Marshal(errMap)
	http.Error(w, string(errJSON), http.StatusInternalServerError)
}

// GetCustomSecret authenticates to vault and returns the secret
func GetCustomSecret(config *viper.Viper) (customSecret CustomSecret, err error) {
	caCertFile := config.Get("vault_cacert_file").(string)
	caCert, err := ioutil.ReadFile(caCertFile)
	if err != nil {
		logrus.Fatal(err)
		return customSecret, err
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
	var token string
	authenticationMethod := config.Get("vault_auth_method").(string)
	switch authenticationMethod {
	case "approle":
		token, err = VaultAppRoleAuthenticate(config)
	default:
		token, err = VaultTLSAuthenticate(config)
	}
	if err != nil || token == "" {
		logrus.Fatal(err)
		return customSecret, err
	}

	secretURL := config.Get("vault_secret_path").(string) + config.Get("application_id").(string) + "." + config.Get("account_name").(string) + "." + config.Get("application_domain").(string)
	secretName := config.Get("secret_name").(string)
	if secretName != "" {
		secretURL = secretURL + "/" + secretName
	}
	secretRequest, _ := http.NewRequest("GET", secretURL, nil)
	secretRequest.Header.Set("X-Vault-Token", token)
	resp, err := client.Do(secretRequest)

	if err != nil || resp == nil || resp.StatusCode != http.StatusOK {
		logrus.Fatal(err)
		return customSecret, err
	}

	var htmlData []byte
	var vaultSecret VaultSecret
	htmlData, _ = ioutil.ReadAll(resp.Body)
	err = json.Unmarshal(htmlData, &vaultSecret)
	if err != nil {
		logrus.Fatal(err)
		return customSecret, err
	}

	bytes := []byte(vaultSecret.Data.Value)
	err = json.Unmarshal(bytes, &customSecret)
	if err != nil {
		logrus.Fatal(err)
		return customSecret, err
	}
	return customSecret, nil
}
