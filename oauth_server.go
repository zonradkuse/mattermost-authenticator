package oauth

import (
	"database/sql"
	"encoding/json"
	"github.com/RangelReale/osin"
	"github.com/felipeweb/osin-mysql"
	"log"
	"net/http"
)

type OAuthServer struct {
	server        *osin.Server
	store         *mysql.Storage
	authenticator OAuthAuthenticatorBackend
	loginHandler  http.HandlerFunc
}

func NewOAuthServer(sqlConn *sql.DB, schemaPrefix string, config *osin.ServerConfig, backend OAuthAuthenticatorBackend, loginHandler http.HandlerFunc) OAuthServer {
	var authServer OAuthServer
	store := mysql.New(sqlConn, schemaPrefix)
	if err := store.CreateSchemas(); err != nil {
		panic(err)
	}

	authServer.store = store
	authServer.server = osin.NewServer(config, store)
	authServer.authenticator = backend
	authServer.loginHandler = loginHandler

	return authServer
}

func (this *OAuthServer) CreateClient(id, secret, redirectUri string) {
	var client oAuthClient
	client.Id = id
	client.Secret = secret
	client.RedirectUri = redirectUri

	this.store.CreateClient(client)
}

func (this *OAuthServer) RemoveClient(id string) {
	this.store.RemoveClient(id)
}

func (this *OAuthServer) HandleTokenRequest(w http.ResponseWriter, r *http.Request) {
	resp := this.server.NewResponse()
	defer resp.Close()

	if ar := this.server.HandleAccessRequest(resp, r); ar != nil {
		ar.Authorized = true
		this.server.FinishAccessRequest(resp, r, ar)
	}

	if resp.IsError && resp.InternalError != nil {
		log.Printf("ERROR: %s\n", resp.InternalError)
	}

	osin.OutputJSON(resp, w, r)
}

func (this *OAuthServer) HandleTokenInfoRequest(w http.ResponseWriter, r *http.Request) {
	resp := this.server.NewResponse()
	defer resp.Close()

	if ir := this.server.HandleInfoRequest(resp, r); ir != nil {
		this.server.FinishInfoRequest(resp, r, ir)
	}

	osin.OutputJSON(resp, w, r)
}

func (this *OAuthServer) HandleUserInfoRequest(w http.ResponseWriter, r *http.Request) {
	resp := this.server.NewResponse()
	defer resp.Close()

	if ir := this.server.HandleInfoRequest(resp, r); ir != nil {
		user, err := this.authenticator.GetUserById(ir.AccessData.UserData.(string))
		if err == nil {
			js, err := json.Marshal(user)

			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			w.Write(js)
			return
		} else {
			resp.ErrorStatusCode = 500
			resp.SetError(osin.E_SERVER_ERROR, "")
			log.Printf("ERROR: %s\n", resp.InternalError)
		}
	}

	osin.OutputJSON(resp, w, r)
}

func (this *OAuthServer) HandleAuthorizeRequest(w http.ResponseWriter, r *http.Request) {
	resp := this.server.NewResponse()
	defer resp.Close()

	if ar := this.server.HandleAuthorizeRequest(resp, r); ar != nil {
		err := r.ParseForm()
		if err != nil {
			this.server.FinishAuthorizeRequest(resp, r, ar)
			osin.OutputJSON(resp, w, r)
			return
		}

		username := r.PostFormValue("username")
		password := r.PostFormValue("password")
		err, userId := this.authenticator.Authenticate(username, password)
		if err == nil && userId != "" {
			ar.UserData = userId
			ar.Authorized = true
		} else {
			this.loginHandler(w, r)
			return
		}

		this.server.FinishAuthorizeRequest(resp, r, ar)
	}

	if resp.IsError && resp.InternalError != nil {
		log.Printf("ERROR: %s\n", resp.InternalError)
	}

	osin.OutputJSON(resp, w, r)
}
