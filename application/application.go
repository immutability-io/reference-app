package application

import (
	"github.com/carbocation/interpose"
	gorilla_mux "github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/spf13/viper"
	"net/http"

	"github.com/immutability-io/reference-app/handlers"
	"github.com/immutability-io/reference-app/middlewares"
)

// New is the constructor for Application struct.
func New(config *viper.Viper) (*Application, error) {
	cookieStoreSecret := config.Get("cookie_secret").(string)

	app := &Application{}
	app.config = config
	app.sessionStore = sessions.NewCookieStore([]byte(cookieStoreSecret))

	return app, nil
}

// Application is the application object that runs HTTP server.
type Application struct {
	config       *viper.Viper
	sessionStore sessions.Store
}

func (app *Application) MiddlewareStruct() (*interpose.Middleware, error) {
	middle := interpose.New()
	middle.Use(middlewares.SetSessionStore(app.sessionStore))

	middle.UseHandler(app.mux())

	return middle, nil
}

func (app *Application) mux() *gorilla_mux.Router {
	router := gorilla_mux.NewRouter()

	router.Handle("/", middlewares.MustLogin(app.config, http.HandlerFunc(handlers.GetHome(app.config)))).Methods("GET")
	router.Handle("/logout", middlewares.MustLogin(app.config, http.HandlerFunc(handlers.Logout(app.config)))).Methods("GET")
	router.Handle("/metadata", middlewares.MustLogin(app.config, http.HandlerFunc(handlers.GetIdentityDocument(app.config)))).Methods("GET")
	router.Handle("/secret", middlewares.MustLogin(app.config, http.HandlerFunc(handlers.GetSecret(app.config)))).Methods("GET")
	router.Handle("/health", http.HandlerFunc(handlers.GetHealth(app.config))).Methods("GET")

	// Path of static files must be last!
	router.PathPrefix("/").Handler(http.FileServer(http.Dir("/content/static")))

	return router
}
