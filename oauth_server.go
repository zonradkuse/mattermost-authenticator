package oauth

import (
	"context"
	"database/sql"
	"encoding/json"
	"github.com/RangelReale/osin"
	"github.com/felipeweb/osin-mysql"
	"log"
	"net/http"
)

// Server is a OAuth server
type Server struct {
	server        *osin.Server
	store         *mysql.Storage
	authenticator AuthenticatorBackend
	loginHandler  http.HandlerFunc
}

// NewServer creates a new OAuth Server with given osin-config
func NewServer(sqlConn *sql.DB, schemaPrefix string, config *osin.ServerConfig, backend AuthenticatorBackend, loginHandler http.HandlerFunc) Server {
	var authServer Server
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

// CreateClient stores a new (id, secret) into the database
func (server *Server) CreateClient(id, secret, redirectURI string) {
	var client osin.DefaultClient
	client.Id = id
	client.Secret = secret
	client.RedirectUri = redirectURI

	server.store.CreateClient(&client)
}

// RemoveClient removes a (id, secret)-tuple from the database again.
func (server *Server) RemoveClient(id string) {
	server.store.RemoveClient(id)
}

// HandleTokenRequest is a http handler to handle to token request
func (server *Server) HandleTokenRequest(w http.ResponseWriter, r *http.Request) {
	resp := server.server.NewResponse()
	defer resp.Close()

	if ar := server.server.HandleAccessRequest(resp, r); ar != nil {
		ar.Authorized = true
		server.server.FinishAccessRequest(resp, r, ar)
	}

	if resp.IsError && resp.InternalError != nil {
		log.Printf("ERROR: %s\n", resp.InternalError)
	}

	osin.OutputJSON(resp, w, r)
}

// HandleTokenInfoRequest is a http handler to handle to tokeninfo request
func (server *Server) HandleTokenInfoRequest(w http.ResponseWriter, r *http.Request) {
	resp := server.server.NewResponse()
	defer resp.Close()

	if ir := server.server.HandleInfoRequest(resp, r); ir != nil {
		server.server.FinishInfoRequest(resp, r, ir)
	}

	osin.OutputJSON(resp, w, r)
}

// HandleUserInfoRequest is a http handler to handle to userinfo request
func (server *Server) HandleUserInfoRequest(w http.ResponseWriter, r *http.Request) {
	resp := server.server.NewResponse()
	defer resp.Close()

	if ir := server.server.HandleInfoRequest(resp, r); ir != nil {
		err, user := server.authenticator.GetUserByID(ir.AccessData.UserData.(string))
		if err == nil && user != nil {
			js, err := json.Marshal(user)

			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			w.Write(js)
			return
		}

		resp.ErrorStatusCode = 500
		resp.SetError(osin.E_SERVER_ERROR, "")
		log.Printf("ERROR: %s\n", resp.InternalError)

	}

	osin.OutputJSON(resp, w, r)
}

// HandleAuthorizeRequest is a http handler to handle to authorize request
func (server *Server) HandleAuthorizeRequest(w http.ResponseWriter, r *http.Request) {
	resp := server.server.NewResponse()
	defer resp.Close()

	if ar := server.server.HandleAuthorizeRequest(resp, r); ar != nil {
		err := r.ParseForm()
		if err != nil {
			server.server.FinishAuthorizeRequest(resp, r, ar)
			osin.OutputJSON(resp, w, r)
			return
		}

		username := r.PostFormValue("username")
		password := r.PostFormValue("password")
		userID, err := server.authenticator.Authenticate(username, password)
		if err != nil || userID == "" {
			// serve the login page again if the authentication fails
			log.Printf("ERROR: Could not authenticate user %s and got error %+v", username, err)
			ctx := context.WithValue(r.Context(), "hasError", true)
			ctx = context.WithValue(ctx, "error", "Invalid Credentials.")

			server.loginHandler(w, r.WithContext(ctx))
			return
		}

		ar.UserData = userID
		ar.Authorized = true

		server.server.FinishAuthorizeRequest(resp, r, ar)
	}

	if resp.IsError && resp.InternalError != nil {
		log.Printf("ERROR: %s\n", resp.InternalError)
	}

	osin.OutputJSON(resp, w, r)
}
