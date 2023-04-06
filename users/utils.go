package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

type CtxKey string

const (
	CTX_USER_DATA CtxKey = "user_data"
)

func MakeAuthCtx(ctx context.Context, data ContextAuthData) (context.Context, error) {
	b, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	return context.WithValue(ctx, CTX_USER_DATA, b), nil
}

func ParseAuthCtx(ctx context.Context) (*ContextAuthData, error) {
	v := ctx.Value(CTX_USER_DATA)
	if v == nil {
		return nil, errors.New("cannot get user data from context")
	}
	ctxData, ok := v.([]byte)
	if !ok {
		return nil, errors.New("context data is not slice of bytes")
	}
	var cd ContextAuthData
	err := json.Unmarshal(ctxData, &cd)
	if err != nil {
		return nil, err
	}

	return &cd, nil
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

	b, err := json.Marshal(userData)
	if err != nil {
		return nil, err
	}

	var tud TokenUserData
	err = json.Unmarshal(b, &tud)
	if err != nil {
		return nil, err
	}

	return &tud, nil
}

func makeResponse(w http.ResponseWriter, body any, err error, status int) {
	w.WriteHeader(status)

	if err != nil {
		strErr := err.Error()
		json.NewEncoder(w).Encode(DefaultResponse{
			Error: &strErr,
			Body:  body,
		})
		return
	}
	json.NewEncoder(w).Encode(DefaultResponse{
		Error: nil,
		Body:  body,
	})
}

func ExtractAccessToken(header http.Header) (string, error) {
	refreshToken := header.Get(HEADER_ACCESS)
	if refreshToken == "" {
		return "", errors.New("provide access token")
	}

	return refreshToken, nil
}

func ExtractRefreshToken(header http.Header) (string, error) {
	refreshToken := header.Get(HEADER_REFRESH)
	if refreshToken == "" {
		return "", errors.New("provide refresh token")
	}

	return refreshToken, nil
}

func ExtractUserIdVar(r *http.Request) (string, error) {
	vars := mux.Vars(r)
	userId := vars["uuid"]
	_, err := uuid.Parse(userId)
	if err != nil || uuid.IsInvalidLengthError(err) {
		return "", errors.New("invalid user id")
	}

	return userId, nil
}

func DecodeRequestBody[T any](r io.ReadCloser) (T, error) {
	var decoded T
	err := json.NewDecoder(r).Decode(&decoded)
	if err != nil {
		return decoded, err
	}

	return decoded, nil
}
