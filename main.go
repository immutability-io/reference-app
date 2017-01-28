package main

import (
	"fmt"
	"github.com/Sirupsen/logrus"
	"github.com/immutability-io/reference-app/application"
	"github.com/spf13/viper"
	"github.com/tylerb/graceful"
	"net/http"
	"os"
	"time"
)

func newConfig() (*viper.Viper, error) {
	c := viper.New()
	c.SetConfigName("config")       // name of config file (without extension)
	c.AddConfigPath("/etc/golang/") // path to look for the config file in
	c.AddConfigPath(".")            // optionally look for config in the working directory
	err := c.ReadInConfig()         // Find and read the config file
	if err != nil {                 // Handle errors reading the config file
		panic(fmt.Errorf("Fatal error config file: %s \n", err))
	}
	return c, nil
}

func main() {
	config, err := newConfig()
	logfile := config.Get("debug_file").(string) + config.Get("application_id").(string) + ".log"
	f, err := os.OpenFile(logfile, os.O_WRONLY|os.O_CREATE, 0755)
	if err != nil {
		return
	}
	logrus.SetOutput(f)
	logrus.SetLevel(logrus.DebugLevel)
	logrus.Debug(logfile)
	if err != nil {
		logrus.Fatal(err)
	}

	app, err := application.New(config)
	if err != nil {
		logrus.Fatal(err)
	}

	middle, err := app.MiddlewareStruct()
	if err != nil {
		logrus.Fatal(err)
	}

	serverAddress := config.Get("http_addr").(string)

	certFile := config.Get("http_cert_file").(string)
	keyFile := config.Get("http_key_file").(string)
	drainIntervalString := config.Get("http_drain_interval").(string)

	drainInterval, err := time.ParseDuration(drainIntervalString)
	if err != nil {
		logrus.Fatal(err)
	}

	srv := &graceful.Server{
		Timeout: drainInterval,
		Server:  &http.Server{Addr: serverAddress, Handler: middle},
	}

	logrus.Infoln("Running HTTP server on " + serverAddress)

	if certFile != "" && keyFile != "" {
		err = srv.ListenAndServeTLS(certFile, keyFile)
	} else {
		err = srv.ListenAndServe()
	}

	if err != nil {
		logrus.Fatal(err)
	}
}
