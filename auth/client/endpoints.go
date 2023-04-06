package auth_client

type Endpoint struct {
	Path   string
	Method string
}

type EndpointName string

const (
	E_TOKEN    EndpointName = "token"
	E_VALIDATE EndpointName = "validate"
	E_REFRESH  EndpointName = "refresh"
	E_USER_ID  EndpointName = "user-id"
	E_REVOKE   EndpointName = "revoke"
)

var endpoints map[EndpointName]Endpoint = map[EndpointName]Endpoint{
	E_TOKEN: {
		Path:   "/token",
		Method: "POST",
	},
	E_VALIDATE: {
		Path:   "/validate",
		Method: "POST",
	},
	E_REFRESH: {
		Path:   "/refresh",
		Method: "PUT",
	},
	E_USER_ID: {
		Path:   "/user-id",
		Method: "POST",
	},
	E_REVOKE: {
		Path:   "/revoke",
		Method: "DELETE",
	},
}
