package main

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/golang-jwt/jwt"
	"github.com/gorilla/mux"
)

const (
	HEADER_REFRESH      = "X-Refresh-Token"
	HEADER_ACCESS       = "X-Access-Token"
	HEADER_MW_TOKEN     = "X-MW-Token"
	HEADER_SERVICE_NAME = "X-Service-Name"
)

type TokenUserData struct {
	RoleId int `json:"role_id"`
}

func ParseJWTClaims(token string, publicKey []byte) (*TokenUserData, error) {
	jwtToken, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		key, err := jwt.ParseRSAPublicKeyFromPEM(publicKey)
		if err != nil {
			return nil, err
		}
		return key, nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := jwtToken.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("not valid token claims")
	}

	userData, ok := claims["user_claims"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("not valid type of claims. Got %t want %q", claims["user_claims"], "TokenUserData")
	}

	roleIdValue, ok := userData["role_id"]
	if !ok {
		return nil, fmt.Errorf("token should have 'role_id'")
	}

	roleId, ok := roleIdValue.(float64)
	if !ok {
		return nil, fmt.Errorf("not valid type of 'role_id' field. Expected 'float64' got %t", roleIdValue)
	}

	return &TokenUserData{
		RoleId: int(roleId),
	}, nil
}

func ExtractAccessToken(header http.Header) (string, error) {
	accessToken := header.Get(HEADER_ACCESS)
	if accessToken == "" {
		return "", errors.New("provide access token")
	}

	return accessToken, nil
}

func ExtractRefreshToken(header http.Header) (string, error) {
	refreshToken := header.Get(HEADER_REFRESH)
	if refreshToken == "" {
		return "", errors.New("provide refresh token")
	}

	return refreshToken, nil
}

func sendRequest(client *http.Client, w http.ResponseWriter, r *http.Request, host url.URL, endpoint string, method string, body io.ReadCloser) error {
	reqHost := host.JoinPath(endpoint).String()
	log.Println(method, endpoint)
	request, err := http.NewRequest(method, reqHost, body)
	if err != nil {
		return err
	}

	for k, vv := range r.Header {
		for _, v := range vv {
			request.Header.Add(k, v)
		}
	}

	if clientIP, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		request.Header.Set("X-Forwarded-For", clientIP)
	}

	response, err := client.Do(request)
	if err != nil {
		return err
	}

	b, err := io.ReadAll(response.Body)
	if err != nil {
		return err
	}

	w.WriteHeader(response.StatusCode)
	w.Write(b)

	return nil
}

func (s *Server) makeHandlerFunc(client *http.Client, host url.URL, endpoint string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		for key, value := range vars {
			endpoint = strings.Replace(endpoint, fmt.Sprintf("{%s}", key), value, 1)
		}
		err := sendRequest(client, w, r, host, endpoint, r.Method, r.Body)
		if err != nil {
			log.Println(err)
		}
	}
}

func (s *Server) makeMWTokenMiddleware() mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := r.Header.Get(HEADER_MW_TOKEN)
			if token == "" {
				http.Error(w, fmt.Sprintf("provide %q header", HEADER_MW_TOKEN), http.StatusForbidden)
				return
			}
			serviceName := r.Header.Get(HEADER_SERVICE_NAME)
			if serviceName == "" {
				http.Error(w, fmt.Sprintf("provide %q header", HEADER_SERVICE_NAME), http.StatusForbidden)
				return
			}
			err := s.keysController.Validate(token, serviceName)
			if err != nil {
				http.Error(w, err.Error(), http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func (s *Server) makeHeadersMiddleware(headers []string) mux.MiddlewareFunc {
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
