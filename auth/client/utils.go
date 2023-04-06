package auth_client

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
)

func sendRequest[T any](client *http.Client, host *url.URL, en EndpointName, body any) (*T, error) {
	endpoint := endpoints[en]
	reqHost := host.JoinPath(endpoint.Path).String()

	b, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	request, err := http.NewRequest(endpoint.Method, reqHost, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}

	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}

	b, err = io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	var fr AuthResponse[T]
	err = json.Unmarshal(b, &fr)
	if err != nil {
		return nil, err
	}
	if fr.Error != nil {
		return nil, errors.New(*fr.Error)
	}

	return &fr.Body, nil
}
