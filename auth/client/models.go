package auth_client

type TokensRequest struct {
	UserId     string `json:"user_id"`
	UserClaims any    `json:"user_claims"`
}

type TokenResponse struct {
	AccessToken  *string `json:"access_token"`
	RefreshToken *string `json:"refresh_token"`
}

type ValidateRequest struct {
	AccessToken  *string `json:"access_token"`
	RefreshToken *string `json:"refresh_token"`
}

type ValidateResponse struct {
	AccessToken  *bool `json:"access_token,omitempty"`
	RefreshToken *bool `json:"refresh_token,omitempty"`
}

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type RefreshResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type GetUserIdRequest struct {
	AccessToken string `json:"access_token"`
}

type GetUserIdResponse string

type RevokeRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type RevokeResponse bool

type AuthResponse[T any] struct {
	Error *string `json:"error"`
	Body  T       `json:"body"`
}
