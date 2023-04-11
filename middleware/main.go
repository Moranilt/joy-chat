package main

import (
	"log"
	"strings"
	"time"

	"net/http"
	"net/url"

	"github.com/Moranilt/joy-chat/middleware/config"
	"github.com/Moranilt/joy-chat/middleware/keys"
	"github.com/gorilla/mux"
	vault "github.com/hashicorp/vault/api"
)

type Server struct {
	keysController *keys.Keys
	vaultClient    *vault.Client
	vaultCfg       *config.VaultConfig
}

func NewServer(kc *keys.Keys, vc *vault.Client, vaultCfg *config.VaultConfig) *Server {
	return &Server{
		keysController: kc,
		vaultClient:    vc,
		vaultCfg:       vaultCfg,
	}
}

func (s *Server) MakeHandlers(hosts []config.Host, publicKey []byte) *mux.Router {
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
			handleFunc := s.makeHandlerFunc(&client, *urlHost, endpoint.Pattern)

			var middleware []mux.MiddlewareFunc

			if len(endpoint.HeadersRequired) > 0 {
				middleware = append(middleware, s.makeHeadersMiddleware(endpoint.HeadersRequired))
			}

			if endpoint.Authentication {
				middleware = append(middleware, makeAuthMiddleware(endpoint.Roles, publicKey))
			}

			if endpoint.MwToken {
				middleware = append(middleware, s.makeMWTokenMiddleware())
			}

			subrouter := prefixRoute.Methods(endpoint.Methods...).Subrouter()
			subrouter.HandleFunc(endpoint.Pattern, handleFunc)
			subrouter.Use(middleware...)
		}
	}

	return router
}

func (s *Server) GenerateKey(w http.ResponseWriter, r *http.Request) {
	serviceName := r.URL.Query().Get("service_name")
	if serviceName == "" {
		http.Error(w, "provide 'service_name' query param", http.StatusBadRequest)
		return
	}

	newKey := s.keysController.Sign(serviceName)
	filePath := strings.Join([]string{s.vaultCfg.TokensStore, serviceName}, "/")
	data := map[string]any{
		"token": newKey,
	}
	_, err := s.vaultClient.KVv2(s.vaultCfg.MountPath).Put(r.Context(), filePath, data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusCreated)
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

	publicAuthKey, err := config.VaultAuthPublicKey(vaultClient, &env.Vault)
	if err != nil {
		log.Fatal(err)
	}

	keysController := keys.NewKeys(vaultClient, &env.Vault)
	if env.GenerateKeys {
		err := keysController.GenerateKeys(keys.DEFAULT_BIT_SIZE)
		if err != nil {
			log.Fatal(err)
		}

		err = keysController.StoreToVault()
		if err != nil {
			log.Fatal(err)
		}
	} else {
		err := keysController.GetFromVault()
		if err != nil {
			log.Fatal(err)
		}
	}

	server := NewServer(keysController, vaultClient, &env.Vault)

	router := server.MakeHandlers(cfg.Hosts, publicAuthKey)
	router.HandleFunc("/key", server.GenerateKey).Methods(http.MethodGet)

	log.Fatal(http.ListenAndServe(":"+env.Port, router))
}
