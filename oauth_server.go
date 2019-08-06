package oauth

import (
	"context"
	"database/sql"
	"encoding/json"
	"html/template"
	"log"
	"net/http"

	"github.com/RangelReale/osin"
	mysql "github.com/felipeweb/osin-mysql"
	"github.com/pkg/errors"
)

// Server is a OAuth server
type Server struct {
	osin *osin.Server

	store         *mysql.Storage
	authenticator AuthenticatorBackend

	AuthorizeHandler func(http.ResponseWriter, *http.Request)
	TokenHandler     func(http.ResponseWriter, *http.Request)
	TokenInfoHandler func(http.ResponseWriter, *http.Request)
	LoginHandler     func(http.ResponseWriter, *http.Request)

	// TemplatePath is a relative, slash terminated, path holding the used templates to render
	TemplatePath string
}

// NewServer creates a new Server with default handlers
func NewServer(conn *sql.DB, prefix string, config *osin.ServerConfig, backend AuthenticatorBackend) Server {
	server := NewServerWithCustomHandlers(conn, prefix, config, backend)

	server.AuthorizeHandler = server.HandleAuthorizeRequest
	server.TokenHandler = server.HandleTokenRequest
	server.TokenInfoHandler = server.HandleTokenInfoRequest
	server.LoginHandler = server.HandleLoginRequest

	server.TemplatePath = "templates/"

	return server
}

// NewServerWithCustomHandlers creates a new OAuth Server with given osin-config
func NewServerWithCustomHandlers(sqlConn *sql.DB, schemaPrefix string, config *osin.ServerConfig, backend AuthenticatorBackend) Server {
	store := mysql.New(sqlConn, schemaPrefix)
	if err := store.CreateSchemas(); err != nil {
		panic(err)
	}

	var authServer Server

	authServer.osin = osin.NewServer(config, store)

	authServer.store = store
	authServer.authenticator = backend

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
	resp := server.osin.NewResponse()
	defer resp.Close()

	if ar := server.osin.HandleAccessRequest(resp, r); ar != nil {
		ar.Authorized = true
		server.osin.FinishAccessRequest(resp, r, ar)
	}

	if resp.IsError && resp.InternalError != nil {
		log.Printf("ERROR: %s\n", resp.InternalError)
	}

	osin.OutputJSON(resp, w, r)
}

// HandleTokenInfoRequest is a http handler to handle to tokeninfo request
func (server *Server) HandleTokenInfoRequest(w http.ResponseWriter, r *http.Request) {
	resp := server.osin.NewResponse()
	defer resp.Close()

	if ir := server.osin.HandleInfoRequest(resp, r); ir != nil {
		server.osin.FinishInfoRequest(resp, r, ir)
	}

	osin.OutputJSON(resp, w, r)
}

// HandleUserInfoRequest is a http handler to handle to userinfo request
func (server *Server) HandleUserInfoRequest(w http.ResponseWriter, r *http.Request) {
	resp := server.osin.NewResponse()
	defer resp.Close()

	if ir := server.osin.HandleInfoRequest(resp, r); ir != nil {
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
	resp := server.osin.NewResponse()
	defer resp.Close()

	if ar := server.osin.HandleAuthorizeRequest(resp, r); ar != nil {
		err := r.ParseForm()
		if err != nil {
			server.osin.FinishAuthorizeRequest(resp, r, ar)
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

			server.LoginHandler(w, r.WithContext(ctx))
			return
		}

		ar.UserData = userID
		ar.Authorized = true

		server.osin.FinishAuthorizeRequest(resp, r, ar)
	}

	if resp.IsError && resp.InternalError != nil {
		log.Printf("ERROR: %s\n", resp.InternalError)
	}

	osin.OutputJSON(resp, w, r)
}

// HandleLoginRequest is a http handler to handle login requests
func (server *Server) HandleLoginRequest(w http.ResponseWriter, r *http.Request) {
	renderTemplate(server.TemplatePath, w, "index.html")
}

func renderTemplate(templatePath string, w http.ResponseWriter, id string) {
	renderTemplateWithData(templatePath, w, id, "")
}

// renderTemplate is a convenience helper for rendering templates.
func renderTemplateWithData(templatePath string, w http.ResponseWriter, id string, d interface{}) bool {
	if t, err := template.New(id).ParseFiles(templatePath + id); err != nil {
		http.Error(w, errors.Wrap(err, "Could not render template").Error(), http.StatusInternalServerError)
		return false
	} else if err := t.Execute(w, d); err != nil {
		http.Error(w, errors.Wrap(err, "Could not render template").Error(), http.StatusInternalServerError)
		return false
	}
	return true
}
