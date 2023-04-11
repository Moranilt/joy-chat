package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"

	auth_client "github.com/Moranilt/joy-chat/auth/client"
	"github.com/Moranilt/joy-chat/users/config"
	"github.com/Moranilt/joy-chat/users/user"
	"github.com/gorilla/mux"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

const (
	_ = iota
	ROLE_DEFAULT
	ROLE_MODERATOR
	ROLE_ADMIN
)

const (
	HEADER_REFRESH = "X-Refresh-Token"
	HEADER_ACCESS  = "X-Access-Token"
)

type Server struct {
	cfg        *config.Config
	db         *sqlx.DB
	authClient *auth_client.AuthClient
	userClient user.UserController
	publicKey  []byte
}

func NewServer(cfg *config.Config, db *sqlx.DB, authClient *auth_client.AuthClient, userClient user.UserController, publicKey []byte) *Server {
	return &Server{
		cfg:        cfg,
		db:         db,
		authClient: authClient,
		publicKey:  publicKey,
		userClient: userClient,
	}
}

func (s *Server) SignIn(w http.ResponseWriter, r *http.Request) {
	var reqBody user.EmailAndPasswordRequest
	err := json.NewDecoder(r.Body).Decode(&reqBody)
	if err != nil {
		makeResponse(w, nil, err, http.StatusBadRequest)
		return
	}

	userData, err := s.userClient.GetByEmailAndPassword(reqBody)
	if err != nil {
		makeResponse(w, nil, err, http.StatusBadRequest)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(userData.Password), []byte(reqBody.Password)); err != nil {
		makeResponse(w, nil, errors.New("not valid password"), http.StatusBadRequest)
		return
	}

	err = s.userClient.UpdateLastLogin(userData.ID)
	if err != nil {
		makeResponse(w, nil, err, http.StatusBadRequest)
		return
	}

	resp, err := s.authClient.Tokens(auth_client.TokensRequest{
		UserId: userData.ID,
		UserClaims: TokenUserData{
			Firstname:  userData.Firstname,
			Lastname:   userData.Lastname,
			Patronymic: *userData.Patronymic,
			RoleId:     userData.RoleId,
		},
	})
	if err != nil {
		makeResponse(w, nil, err, http.StatusBadRequest)
		return
	}

	makeResponse(w, resp, nil, http.StatusOK)
}

func (s *Server) Logout(w http.ResponseWriter, r *http.Request) {
	refreshToken, err := ExtractRefreshToken(r.Header)
	if err != nil {
		makeResponse(w, nil, err, http.StatusBadRequest)
		return
	}

	revoked, err := s.authClient.Revoke(auth_client.RevokeRequest{
		RefreshToken: refreshToken,
	})
	if err != nil {
		makeResponse(w, nil, err, http.StatusBadRequest)
		return
	}

	makeResponse(w, revoked, nil, http.StatusOK)
}

func (s *Server) SignUp(w http.ResponseWriter, r *http.Request) {
	var cur user.CreateUserRequest
	err := json.NewDecoder(r.Body).Decode(&cur)
	if err != nil {
		makeResponse(w, nil, err, http.StatusBadRequest)
		return
	}

	resp, err := s.userClient.CreateUser(cur)
	if err != nil {
		makeResponse(w, nil, err, http.StatusBadRequest)
		return
	}

	tokens, err := s.authClient.Tokens(auth_client.TokensRequest{
		UserId: resp.UserId,
		UserClaims: TokenUserData{
			Firstname:  cur.Firstname,
			Lastname:   cur.Lastname,
			Patronymic: *cur.Patronymic,
			RoleId:     resp.RoleId,
		},
	})
	if err != nil {
		makeResponse(w, nil, err, http.StatusBadRequest)
		return
	}

	makeResponse(w, tokens, nil, http.StatusOK)
}

func (s *Server) Refresh(w http.ResponseWriter, r *http.Request) {
	refreshToken, err := ExtractRefreshToken(r.Header)
	if err != nil {
		makeResponse(w, nil, err, http.StatusBadRequest)
		return
	}

	newTokens, err := s.authClient.Refresh(auth_client.RefreshRequest{
		RefreshToken: refreshToken,
	})
	if err != nil {
		makeResponse(w, nil, err, http.StatusBadRequest)
		return
	}

	makeResponse(w, newTokens, nil, http.StatusCreated)
}

func (s *Server) UserGet(w http.ResponseWriter, r *http.Request) {
	userData, err := ParseAuthCtx(r.Context())
	if err != nil {
		makeResponse(w, nil, err, http.StatusBadRequest)
		return
	}

	user, err := s.userClient.GetWithoutID(userData.UserId)
	if err != nil {
		makeResponse(w, nil, err, http.StatusBadRequest)
		return
	}

	makeResponse(w, user, nil, http.StatusOK)
}

func (s *Server) UserUpdate(w http.ResponseWriter, r *http.Request) {
	userData, err := ParseAuthCtx(r.Context())
	if err != nil {
		makeResponse(w, nil, err, http.StatusBadRequest)
		return
	}

	var reqBody user.UserUpdateRequest
	err = json.NewDecoder(r.Body).Decode(&reqBody)
	if err != nil {
		makeResponse(w, nil, err, http.StatusBadRequest)
		return
	}

	updated, err := s.userClient.Update(userData.UserId, reqBody)
	if err != nil {
		makeResponse(w, updated, err, http.StatusBadRequest)
		return
	}

	makeResponse(w, updated, nil, http.StatusOK)
}

func (s *Server) UserDelete(w http.ResponseWriter, r *http.Request) {
	userData, err := ParseAuthCtx(r.Context())
	if err != nil {
		makeResponse(w, false, err, http.StatusBadRequest)
	}

	refreshToken, err := ExtractRefreshToken(r.Header)
	if err != nil {
		makeResponse(w, false, err, http.StatusBadRequest)
		return
	}

	revoked, err := s.authClient.Revoke(auth_client.RevokeRequest{
		RefreshToken: refreshToken,
	})
	if err != nil {
		makeResponse(w, false, err, http.StatusBadRequest)
		return
	}

	if !*revoked {
		makeResponse(w, false, errors.New("cannot revoke tokens"), http.StatusBadRequest)
		return
	}

	deleted, err := s.userClient.Delete(userData.UserId)
	if err != nil {
		makeResponse(w, false, err, http.StatusBadRequest)
		return
	}

	makeResponse(w, deleted, nil, http.StatusOK)
}

func (s *Server) ChangePassword(w http.ResponseWriter, r *http.Request) {
	userData, err := ParseAuthCtx(r.Context())
	if err != nil {
		makeResponse(w, false, err, http.StatusBadRequest)
		return
	}

	var reqBody user.ChangePasswordRequest
	err = json.NewDecoder(r.Body).Decode(&reqBody)
	if err != nil {
		makeResponse(w, false, err, http.StatusBadRequest)
		return
	}

	err = s.userClient.ChangePassword(userData.UserId, reqBody)
	if err != nil {
		makeResponse(w, false, err, http.StatusBadRequest)
		return
	}

	makeResponse(w, true, nil, http.StatusOK)
}

func (s *Server) AdminUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.userClient.AllUsers()
	if err != nil {
		makeResponse(w, nil, err, http.StatusBadRequest)
		return
	}

	makeResponse(w, users, nil, http.StatusOK)
}

func (s *Server) AdminUserByUUID(w http.ResponseWriter, r *http.Request) {
	userId, err := ExtractUserIdVar(r)
	if err != nil {
		makeResponse(w, nil, err, http.StatusBadRequest)
		return
	}

	user, err := s.userClient.GetWithID(userId)
	if err != nil {
		makeResponse(w, nil, err, http.StatusBadRequest)
		return
	}

	makeResponse(w, user, nil, http.StatusOK)
}

func (s *Server) AdminUpdateUser(w http.ResponseWriter, r *http.Request) {
	userId, err := ExtractUserIdVar(r)
	if err != nil {
		makeResponse(w, nil, err, http.StatusBadRequest)
		return
	}

	reqBody, err := DecodeRequestBody[user.UpdateAllFieldsRequest](r.Body)
	if err != nil {
		makeResponse(w, false, err, http.StatusBadRequest)
		return
	}

	err = s.userClient.UpdateAllFields(userId, reqBody)
	if err != nil {
		makeResponse(w, false, err, http.StatusBadRequest)
		return
	}

	makeResponse(w, true, nil, http.StatusOK)
}

func (s *Server) AdminDeleteUsers(w http.ResponseWriter, r *http.Request) {
	deleteIDs, err := DecodeRequestBody[[]string](r.Body)
	if err != nil {
		makeResponse(w, false, err, http.StatusBadRequest)
		return
	}

	err = s.userClient.DeleteUsers(deleteIDs)
	if err != nil {
		makeResponse(w, false, err, http.StatusBadRequest)
		return
	}

	makeResponse(w, true, nil, http.StatusOK)
}

func main() {
	envCfg, err := config.ReadEnv()
	if err != nil {
		log.Fatal(err)
	}

	var cfg config.Config
	err = config.ReadConsulConfig(&envCfg.Consul, &cfg)
	if err != nil {
		log.Fatal(err)
	}

	source := fmt.Sprintf(
		"host=%s port=%d dbname=%s user=%s password=%s sslmode=%s",
		cfg.DB.Host, cfg.DB.Port, cfg.DB.DBName, cfg.DB.User, cfg.DB.Password, cfg.DB.Sslmode,
	)
	db, err := sqlx.Open("postgres", source)
	if err != nil {
		log.Fatal(err)
	}

	if err := db.Ping(); err != nil {
		log.Fatal(err)
	}

	vaultClient, err := config.NewVaultClient(&envCfg.Vault)
	if err != nil {
		log.Fatal(err)
	}

	publicKey, err := config.VaultPublicKey(vaultClient, &envCfg.Vault)
	if err != nil {
		log.Fatal(err)
	}

	authClient, err := auth_client.NewClient(envCfg.AuthHost)
	if err != nil {
		log.Fatal(err)
	}

	userClient := user.NewUserClient(db)

	server := NewServer(&cfg, db, authClient, userClient, publicKey)
	router := mux.NewRouter()
	secure := router.PathPrefix("/user").Subrouter()
	secure.Use(server.authMiddleware)
	secure.HandleFunc("/", server.UserUpdate).Methods(http.MethodPatch)
	secure.HandleFunc("/", server.UserDelete).Methods(http.MethodDelete)
	secure.HandleFunc("/", server.UserGet).Methods(http.MethodGet)
	secure.HandleFunc("/change-password", server.ChangePassword).Methods(http.MethodPut)

	admin := router.PathPrefix("/admin").Subrouter().StrictSlash(true)
	admin.HandleFunc("/users", server.AdminUsers).Methods(http.MethodGet)
	admin.HandleFunc("/users/{uuid}", server.AdminUserByUUID).Methods(http.MethodGet)
	admin.HandleFunc("/users/{uuid}", server.AdminUpdateUser).Methods(http.MethodPatch)
	admin.HandleFunc("/users", server.AdminDeleteUsers).Methods(http.MethodDelete)

	router.HandleFunc("/sign-in", server.SignIn).Methods(http.MethodPost)
	router.HandleFunc("/sign-up", server.SignUp).Methods(http.MethodPost)
	router.HandleFunc("/logout", server.Logout).Methods(http.MethodDelete)
	router.HandleFunc("/refresh", server.Refresh).Methods(http.MethodPut)

	log.Fatal(http.ListenAndServe(":"+envCfg.Port, router))
}

func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		accessToken, err := ExtractAccessToken(r.Header)
		if err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		userId, err := s.authClient.GetUserId(auth_client.GetUserIdRequest{
			AccessToken: accessToken,
		})

		if err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusForbidden)
			return
		}

		newCtx, err := MakeAuthCtx(r.Context(), ContextAuthData{
			UserId: *userId,
		})
		if err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		next.ServeHTTP(w, r.WithContext(newCtx))
	})
}
