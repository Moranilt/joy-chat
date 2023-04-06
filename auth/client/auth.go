package auth_client

import (
	"net/http"
	"net/url"
	"time"
)

type AuthClient struct {
	host   *url.URL
	client *http.Client
}

func NewClient(host string) (*AuthClient, error) {
	h, err := url.Parse(host)
	if err != nil {
		return nil, err
	}
	return &AuthClient{
		host: h,
		client: &http.Client{
			Timeout:       15 * time.Second,
			Transport:     http.DefaultTransport,
			CheckRedirect: http.DefaultClient.CheckRedirect,
		},
	}, nil
}

func (a *AuthClient) Tokens(body TokensRequest) (*TokenResponse, error) {
	resp, err := sendRequest[TokenResponse](a.client, a.host, E_TOKEN, body)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func (a *AuthClient) Validate(body ValidateRequest) (*ValidateResponse, error) {
	resp, err := sendRequest[ValidateResponse](a.client, a.host, E_VALIDATE, body)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func (a *AuthClient) Refresh(body RefreshRequest) (*RefreshResponse, error) {
	resp, err := sendRequest[RefreshResponse](a.client, a.host, E_REFRESH, body)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func (a *AuthClient) GetUserId(body GetUserIdRequest) (*string, error) {
	resp, err := sendRequest[string](a.client, a.host, E_USER_ID, body)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func (a *AuthClient) Revoke(body RevokeRequest) (*bool, error) {
	resp, err := sendRequest[bool](a.client, a.host, E_REVOKE, body)
	if err != nil {
		return nil, err
	}

	return resp, nil
}
