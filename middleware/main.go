package main

import (
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/Moranilt/joy-chat/middleware/config"
	"github.com/gorilla/mux"
)

func MakeHandlers(hosts []config.Host, publicKey []byte) *mux.Router {
	client := http.Client{
		Timeout: 15 * time.Second,
	}
	router := mux.NewRouter()
	for _, host := range hosts {
		prefixRoute := router.PathPrefix(host.Prefix).Subrouter()
		urlHost, err := url.Parse(host.Hostname)
		if err != nil {
			log.Fatal("not valid hostname: ", err)
		}
		for _, endpoint := range host.Endpoints {
			handleFunc := makeHandlerFunc(&client, *urlHost, endpoint.Pattern)
			middleware := []mux.MiddlewareFunc{
				makeHeadersMiddleware(endpoint.HeadersRequired),
			}
			if endpoint.Authentication {
				middleware = append(middleware, makeAuthMiddleware(endpoint.Roles, publicKey))
			}
			subrouter := prefixRoute.Methods(endpoint.Methods...).Subrouter()
			subrouter.HandleFunc(endpoint.Pattern, handleFunc)
			subrouter.Use(middleware...)
		}
	}

	return router
}

func makeHandlerFunc(client *http.Client, host url.URL, endpoint string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		err := sendRequest(client, w, r, host, endpoint, r.Method, r.Body)
		if err != nil {
			log.Println(err)
		}
	}
}

func makeHeadersMiddleware(headers []string) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			for _, header := range headers {
				exists := r.Header.Get(header)
				if exists == "" {
					w.WriteHeader(http.StatusNotAcceptable)
					return
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

func makeAuthMiddleware(roles []int, publicKey []byte) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			accessToken, err := ExtractAccessToken(r.Header)
			if err != nil {
				log.Println(err)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			data, err := ParseJWTClaims(accessToken, publicKey)
			if err != nil {
				log.Println(err)
				http.Error(w, "not valid token", http.StatusBadRequest)
				return
			}

			if len(roles) == 0 {
				next.ServeHTTP(w, r)
				return
			}

			for _, role := range roles {
				if data.RoleId == role {
					next.ServeHTTP(w, r)
					return
				}
			}

			log.Println(err)
			w.WriteHeader(http.StatusForbidden)
		})
	}
}

func main() {

	env, err := config.ReadEnv()
	if err != nil {
		log.Fatal(err)
	}

	cfg, err := config.ReadConsulConfig(&env.Consul)
	if err != nil {
		log.Fatal(err)
	}

	vaultClient, err := config.NewVaultClient(&env.Vault)
	if err != nil {
		log.Fatal(err)
	}

	publicKey, err := config.VaultPublicKey(vaultClient, &env.Vault)
	if err != nil {
		log.Fatal(err)
	}

	router := MakeHandlers(cfg.Hosts, publicKey)

	log.Fatal(http.ListenAndServe(":"+env.Port, router))
}
