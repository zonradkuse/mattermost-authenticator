package oauth

type oAuthClient struct {
	Id          string
	Secret      string
	RedirectUri string
	UserData    interface{}
}

func (this oAuthClient) GetId() string {
	return this.Id
}
func (this oAuthClient) GetSecret() string {
	return this.Secret
}
func (this oAuthClient) GetRedirectUri() string {
	return this.RedirectUri
}
func (this oAuthClient) GetUserData() interface{} {
	return this.UserData
}
