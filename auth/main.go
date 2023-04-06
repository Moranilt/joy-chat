package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/Moranilt/joy-chat/auth/config"
	keygen "github.com/Moranilt/joy-chat/auth/keys"
	"github.com/gorilla/mux"
	"github.com/redis/go-redis/v9"
)

type Server struct {
	auth          Authenticator
	consulWatcher config.ConsulWatcher
	consulEnv     *config.EnvConsul
}

func (s *Server) CreateTokens(w http.ResponseWriter, r *http.Request) {
	var rb CreateTokensBody
	err := json.NewDecoder(r.Body).Decode(&rb)
	if err != nil {
		makeResponse(w, nil, err.Error(), http.StatusBadRequest)
		return
	}

	tokens, err := s.auth.CreateTokens(r.Context(), rb.UserId, rb.UserClaims)
	if err != nil {
		makeResponse(w, nil, err.Error(), http.StatusBadRequest)
		return
	}

	makeResponse(w, tokens, "", http.StatusOK)
}

func (s *Server) Validate(w http.ResponseWriter, r *http.Request) {
	var rb ValidateRequest
	err := json.NewDecoder(r.Body).Decode(&rb)
	if err != nil {
		makeResponse(w, nil, err.Error(), http.StatusBadRequest)
		return
	}

	if rb.AccessToken == nil && rb.RefreshToken == nil {
		makeResponse(w, nil, "provide any token to validate", http.StatusBadRequest)
		return
	}

	response := make(map[string]bool)
	if rb.AccessToken != nil {
		response["access_token"] = s.auth.CheckAccessTokenExistence(r.Context(), *rb.AccessToken)
	}

	if rb.RefreshToken != nil {
		response["refresh_token"] = s.auth.CheckRefreshTokenExistence(r.Context(), *rb.RefreshToken)
	}

	makeResponse(w, response, "", http.StatusOK)
}

func (s *Server) Refresh(w http.ResponseWriter, r *http.Request) {
	var rb RefreshRequest
	err := json.NewDecoder(r.Body).Decode(&rb)
	if err != nil {
		makeResponse(w, nil, err.Error(), http.StatusBadRequest)
		return
	}

	newTokens, err := s.auth.Refresh(r.Context(), rb.RefreshToken)
	if err != nil {
		makeResponse(w, nil, err.Error(), http.StatusBadRequest)
		return
	}

	makeResponse(w, newTokens, "", http.StatusOK)
}

func (s *Server) UserID(w http.ResponseWriter, r *http.Request) {
	var rb UserIDRequest
	err := json.NewDecoder(r.Body).Decode(&rb)
	if err != nil {
		makeResponse(w, nil, err.Error(), http.StatusBadRequest)
		return
	}

	userID, err := s.auth.GetUserID(r.Context(), rb.AccessToken)
	if err != nil {
		makeResponse(w, nil, err.Error(), http.StatusBadRequest)
		return
	}

	makeResponse(w, userID, "", http.StatusOK)
}

func (s *Server) Revoke(w http.ResponseWriter, r *http.Request) {
	var rb RefreshRequest
	err := json.NewDecoder(r.Body).Decode(&rb)
	if err != nil {
		makeResponse(w, nil, err.Error(), http.StatusBadRequest)
		return
	}

	err = s.auth.Revoke(r.Context(), rb.RefreshToken)
	if err != nil {
		makeResponse(w, false, err.Error(), http.StatusBadRequest)
		return
	}

	makeResponse(w, true, "", http.StatusOK)
}

func (s *Server) Watch(w http.ResponseWriter, r *http.Request) {
	b, err := io.ReadAll(r.Body)
	if err != nil {
		fmt.Println(err)
		return
	}

	var cb []config.WatchConsulBody
	err = json.Unmarshal(b, &cb)
	if err != nil {
		fmt.Println(err)
		return
	}

	s.consulWatcher.WatchConsul(s.consulEnv, cb)
}

func main() {
	env, err := config.ReadEnv()
	if err != nil {
		log.Fatal(err)
	}

	vaultClient, err := config.NewVaultClient(&env.Vault)
	if err != nil {
		log.Fatal(err)
	}

	if env.GenerateRSAKeys {
		newKeys := keygen.NewKeys(vaultClient, &env.Vault)
		err = newKeys.StoreToVault()
		if err != nil {
			log.Fatal(err)
		}
	}

	cfg := config.NewConfig()
	err = cfg.ReadConfig(&env.Consul)
	if err != nil {
		log.Fatal(err)
	}

	keys, err := cfg.ReadVaultKeys(vaultClient, &env.Vault)
	if err != nil {
		log.Fatal(err)
	}

	redis := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%d", cfg.Redis().Host, cfg.Redis().Port),
		Password: cfg.Redis().Password,
		DB:       cfg.Redis().Db,
	})

	if ping := redis.Ping(context.Background()); ping.Err() != nil {
		log.Fatal(ping.Err())
	}

	auth := NewAuthClient(redis, cfg.JWT(), keys.Private, keys.Public)
	server := Server{
		auth:          auth,
		consulWatcher: cfg,
		consulEnv:     &env.Consul,
	}
	router := mux.NewRouter()

	router.HandleFunc("/token", server.CreateTokens).Methods(http.MethodPost)
	router.HandleFunc("/validate", server.Validate).Methods(http.MethodPost)
	router.HandleFunc("/refresh", server.Refresh).Methods(http.MethodPut)
	router.HandleFunc("/user-id", server.UserID).Methods(http.MethodPost)
	router.HandleFunc("/revoke", server.Revoke).Methods(http.MethodDelete)
	router.HandleFunc("/watch", server.Watch).Methods(http.MethodPost)
	router.Use(contentTypeMiddleware)

	log.Printf("Application running on: http://localhost:%s\n", env.Port)
	log.Fatal(http.ListenAndServe(":"+env.Port, router))
}
