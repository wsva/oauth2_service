package main

import (
	"fmt"
	"net/http"
	"path/filepath"

	"github.com/codegangsta/negroni"
	"github.com/gorilla/mux"
)

func main() {
	err := initGlobals()
	if err != nil {
		fmt.Println(err)
		return
	}

	router := mux.NewRouter()

	router.PathPrefix("/css/").Handler(http.StripPrefix("/css/",
		http.FileServer(http.Dir(filepath.Join(Basepath, "template/css/")))))
	router.PathPrefix("/js/").Handler(http.StripPrefix("/js/",
		http.FileServer(http.Dir(filepath.Join(Basepath, "template/js/")))))

	router.Methods("POST").Path("/signup").Handler(
		negroni.New(
			negroni.HandlerFunc(handleSignUp),
		))
	router.Methods("POST").Path("/signin").Handler(
		negroni.New(
			negroni.HandlerFunc(handleSignIn),
		))
	router.Methods("POST").Path("/token").Handler(
		negroni.New(
			negroni.HandlerFunc(handleToken),
		))
	router.Methods("GET").Path("/authorize").Handler(
		negroni.New(
			negroni.HandlerFunc(handleAuthorize),
		))
	router.Methods("GET").Path("/userinfo").Handler(
		negroni.New(
			negroni.HandlerFunc(handleUserInfo),
		))
	router.Methods("POST").Path("/revoke").Handler(
		negroni.New(
			negroni.HandlerFunc(handleRevoke),
		))
	router.Methods("POST").Path("/introspect").Handler(
		negroni.New(
			negroni.HandlerFunc(handleIntrospect),
		))
	router.Methods("GET").Path("/.well-known/jwks.json").Handler(
		negroni.New(
			negroni.HandlerFunc(handleJwks),
		))
	router.Methods("GET", "POST").Path("/logout").Handler(
		negroni.New(
			negroni.HandlerFunc(handleLogout),
		))
	router.Methods("POST").Path("/account/update").Handler(
		negroni.New(
			negroni.HandlerFunc(handleAccountUpdate),
		))
	router.Methods("GET").Path("/account/all").Handler(
		negroni.New(
			negroni.HandlerFunc(handleAccountAll),
		))
	router.Methods("GET").Path("/menu/all").Handler(
		negroni.New(
			negroni.HandlerFunc(handleMenuAll),
		))
	router.Methods("POST").Path("/menu/access").Handler(
		negroni.New(
			negroni.HandlerFunc(handleCheckMenuAccess),
		))

	router.Methods("GET").Path("/register").Handler(
		negroni.New(
			negroni.HandlerFunc(handleRegister),
		))
	router.Methods("GET").Path("/login").Handler(
		negroni.New(
			negroni.HandlerFunc(handleLogin),
		))
	router.Methods("GET").Path("/").Handler(
		negroni.New(
			negroni.HandlerFunc(handleDashboard),
		))

	server := negroni.New(negroni.NewRecovery())
	//server.Use(bha.NewCORSHandler(nil, nil, nil))
	server.Use(negroni.NewLogger())
	server.UseHandler(router)

	for _, v := range mainConfig.ListenList {
		if !v.Enable {
			continue
		}
		v1 := v
		switch v1.LowercaseProtocol() {
		case "http":
			go func() {
				err = http.ListenAndServe(fmt.Sprintf(":%v", v1.Port),
					server)
				if err != nil {
					fmt.Println(err)
				}
			}()
		case "https":
			go func() {
				s := &http.Server{
					Addr:    fmt.Sprintf(":%v", v1.Port),
					Handler: server,
				}
				s.SetKeepAlivesEnabled(false)
				err = s.ListenAndServeTLS(ServerCrtFile, ServerKeyFile)
				if err != nil {
					fmt.Println(err)
				}
			}()
		}
	}
	select {}
}
