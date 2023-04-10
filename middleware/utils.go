package main

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"

	"github.com/golang-jwt/jwt"
)

const (
	HEADER_REFRESH = "X-Refresh-Token"
	HEADER_ACCESS  = "X-Access-Token"
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
