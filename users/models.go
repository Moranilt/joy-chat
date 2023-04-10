package main

type DefaultResponse struct {
	Error *string `json:"error"`
	Body  any     `json:"body"`
}

type TokenUserData struct {
	Firstname  string `json:"firstname"`
	Lastname   string `json:"lastname"`
	Patronymic string `json:"patronymic"`
	RoleId     int    `json:"role_id"`
}

type ContextAuthData struct {
	UserId string `json:"user_id"`
}
