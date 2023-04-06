package main

import (
	"context"
	"errors"
	"log"
	"time"

	"github.com/Moranilt/joy-chat/auth/config"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

// Reference: https://curity.io/resources/learn/jwt-best-practices/
// https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3

type Stringer interface {
	String() string
}

type Authenticator interface {
	CreateTokens(ctx context.Context, userId string, uc UserClaims) (*AuthTokens, error)
	Revoke(ctx context.Context, refreshToken string) error
	CheckAccessTokenExistence(ctx context.Context, token string) bool
	CheckRefreshTokenExistence(ctx context.Context, token string) bool
	GetUserID(ctx context.Context, accessToken string) (string, error)
	Refresh(ctx context.Context, refreshToken string) (*AuthTokens, error)
}

type Auth struct {
	redis      *redis.Client
	privateKey []byte
	publicKey  []byte
	config     *config.JWTConfig
}

func NewAuthClient(redis *redis.Client, config *config.JWTConfig, privateKey, publicKey []byte) Authenticator {
	return &Auth{
		redis:      redis,
		privateKey: privateKey,
		publicKey:  publicKey,
		config:     config,
	}
}

type UserClaims = map[string]any

type AccessClaims struct {
	UUID       string     `json:"session"`
	UserClaims UserClaims `json:"user_claims"`
	jwt.RegisteredClaims
}

type RefreshClaims struct {
	AccessUUID  string     `json:"access_uuid"`
	RefreshUUID string     `json:"refresh_uuid"`
	UserClaims  UserClaims `json:"user_claims"`
	jwt.RegisteredClaims
}

type AuthTokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

func (a *Auth) makeAccessToken(ctx context.Context, uuid Stringer, uc UserClaims, exp time.Time) (string, error) {
	claims := AccessClaims{
		UUID:       uuid.String(),
		UserClaims: uc,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(exp),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    a.config.Issuer,
			Subject:   a.config.Subject,
			Audience:  a.config.Audience,
			ID:        uuid.String(),
		},
	}

	key, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(a.privateKey))
	if err != nil {
		return "", err
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	access_token, err := token.SignedString(key)
	if err != nil {
		return "", errors.New("cannot create new token. Error: " + err.Error())
	}

	return access_token, nil
}

func (a *Auth) makeRefreshToken(ctx context.Context, accessUUID Stringer, refreshUUID Stringer, uc UserClaims, refreshExp time.Time) (string, error) {
	claims := RefreshClaims{
		AccessUUID:  accessUUID.String(),
		RefreshUUID: refreshUUID.String(),
		UserClaims:  uc,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(refreshExp),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    a.config.Issuer,
			Subject:   a.config.Subject,
			Audience:  a.config.Audience,
			ID:        refreshUUID.String(),
		},
	}
	key, err := jwt.ParseRSAPrivateKeyFromPEM(a.privateKey)
	if err != nil {
		return "", err
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	refresh_token, err := token.SignedString(key)
	if err != nil {
		return "", errors.New("cannot create new token. Error: " + err.Error())
	}

	return refresh_token, nil
}

func (a *Auth) CreateTokens(ctx context.Context, userId string, uc UserClaims) (*AuthTokens, error) {
	accessUUID := uuid.New()
	accessExp := makeTimeFromString(a.config.TTL.Access)

	refreshUUID := uuid.New()
	refreshExp := makeTimeFromString(a.config.TTL.Refresh)

	access_token, err := a.makeAccessToken(ctx, accessUUID, uc, accessExp)
	if err != nil {
		return nil, err
	}

	refresh_token, err := a.makeRefreshToken(ctx, accessUUID, refreshUUID, uc, refreshExp)
	if err != nil {
		return nil, err
	}

	err = a.redis.Set(ctx, accessUUID.String(), userId, time.Until(accessExp)).Err()
	if err != nil {
		return nil, errors.New("cannot store token to redis. Error: " + err.Error())
	}

	err = a.redis.Set(ctx, refreshUUID.String(), userId, time.Until(refreshExp)).Err()
	if err != nil {
		return nil, errors.New("cannot store token to redis. Error: " + err.Error())
	}

	return &AuthTokens{
		AccessToken:  access_token,
		RefreshToken: refresh_token,
	}, nil
}

func (a *Auth) makeJwtOptions(options ...jwt.ParserOption) []jwt.ParserOption {
	var o []jwt.ParserOption
	o = append(o, options...)
	o = append(o, jwt.WithSubject(a.config.Subject), jwt.WithIssuer(a.config.Issuer))
	for _, aud := range a.config.Audience {
		o = append(o, jwt.WithAudience(aud))
	}
	return o
}

func (a *Auth) parseRefreshToken(ctx context.Context, refreshToken string) (*RefreshClaims, error) {
	token, err := jwt.ParseWithClaims(refreshToken, &RefreshClaims{}, func(t *jwt.Token) (interface{}, error) {
		key, err := jwt.ParseRSAPublicKeyFromPEM(a.publicKey)
		if err != nil {
			return nil, err
		}
		return key, nil
	}, a.makeJwtOptions()...)

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*RefreshClaims); ok && token.Valid {
		return claims, nil
	} else {
		return nil, errors.New("not valid token claims")
	}
}

func (a *Auth) parseAccessToken(ctx context.Context, refreshToken string) (*AccessClaims, error) {
	token, err := jwt.ParseWithClaims(refreshToken, &AccessClaims{}, func(t *jwt.Token) (interface{}, error) {
		key, err := jwt.ParseRSAPublicKeyFromPEM(a.publicKey)
		if err != nil {
			return nil, err
		}
		return key, nil
	}, a.makeJwtOptions()...)

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*AccessClaims); ok && token.Valid {
		return claims, nil
	} else {
		return nil, errors.New("not valid token claims")
	}
}

func (a *Auth) Revoke(ctx context.Context, refreshToken string) error {
	claims, err := a.parseRefreshToken(ctx, refreshToken)
	if err != nil {
		return err
	}

	err = a.redis.Del(ctx, claims.RefreshUUID).Err()
	if err != nil {
		return errors.New("cannot delete token from redis. Error: " + err.Error())
	}

	err = a.redis.Del(ctx, claims.AccessUUID).Err()
	if err != nil {
		return errors.New("cannot delete token from redis. Error: " + err.Error())
	}

	return nil
}

func (a *Auth) CheckAccessTokenExistence(ctx context.Context, token string) bool {
	claims, err := a.parseAccessToken(ctx, token)
	if err != nil {
		log.Println(err)
		return false
	}

	result, err := a.redis.Exists(ctx, claims.UUID).Result()
	if err != nil {
		log.Println(err)
		return false
	}

	return result == 1
}

func (a *Auth) CheckRefreshTokenExistence(ctx context.Context, token string) bool {
	claims, err := a.parseRefreshToken(ctx, token)
	if err != nil {
		log.Println(err)
		return false
	}

	result, err := a.redis.Exists(ctx, claims.RefreshUUID).Result()
	if err != nil {
		log.Println(err)
		return false
	}

	return result == 1
}

func (a *Auth) GetUserID(ctx context.Context, accessToken string) (string, error) {
	claims, err := a.parseAccessToken(ctx, accessToken)
	if err != nil {
		return "", err
	}

	userId, err := a.redis.Get(ctx, claims.UUID).Result()
	if err != nil {
		if err == redis.Nil {
			return "", errors.New("token not found")
		}
		return "", err
	}

	return userId, nil
}

func (a *Auth) Refresh(ctx context.Context, refreshToken string) (*AuthTokens, error) {
	claims, err := a.parseRefreshToken(ctx, refreshToken)
	if err != nil {
		return nil, err
	}

	userId, err := a.redis.Get(ctx, claims.RefreshUUID).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, errors.New("refresh token not found")
		}
		return nil, err
	}

	err = a.redis.Del(ctx, claims.RefreshUUID, claims.AccessUUID).Err()
	if err != nil {
		return nil, err
	}

	newTokens, err := a.CreateTokens(ctx, userId, claims.UserClaims)
	if err != nil {
		return nil, err
	}

	return newTokens, err
}
