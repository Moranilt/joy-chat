package main

type DefaultResponse struct {
	Error *string `json:"error"`
	Body  any     `json:"body"`
}

type CreateTokensBody struct {
	UserId     string `json:"user_id"`
	UserClaims `json:"user_claims"`
}

type ValidateRequest struct {
	AccessToken  *string `json:"access_token"`
	RefreshToken *string `json:"refresh_token"`
}

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type UserIDRequest struct {
	AccessToken string `json:"access_token"`
}

type RevokeRequest struct {
	RefreshToken string `json:"refresh_token"`
}
