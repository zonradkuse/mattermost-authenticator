package oauth

type OAuthAuthenticatorBackend interface {
	// Authenticate authenticates the user and returns the unique user identifier
	Authenticate(username, password string) (error, string)

	// GetUserById fetches the user object from the backend without
	GetUserById(id string) (error, interface{})
}
