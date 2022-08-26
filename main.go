package main

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"time"

	oidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"
	"golang.org/x/net/context"
	"golang.org/x/oauth2"
)

var oidcProvider oidc.Provider
var oidcConfig oidc.Config
var oauth2Config oauth2.Config
var idTokenVerifier oidc.IDTokenVerifier

func init() {
	oidcProvider = *createOidcProvider(context.Background())
	oidcConfig, oauth2Config = createConfig(oidcProvider)
	idTokenVerifier = *oidcProvider.Verifier(&oidcConfig)
}

func createOidcProvider(ctx context.Context) *oidc.Provider {
	provider, err := oidc.NewProvider(ctx, "http://localhost:8080/realms/myrealm")

	if err != nil {
		log.Fatal("Failed to fetch discovery document: ", err)
	}

	return provider
}

func createConfig(provider oidc.Provider) (oidc.Config, oauth2.Config) {
	oidcConfig := &oidc.Config{
		ClientID: "mywebapp",
	}

	config := oauth2.Config{
		ClientID:    oidcConfig.ClientID,
		ClientSecret: "hjO5FvMltrSGDgzwnVWrNsLHv5yA7ppP",
		Endpoint:    provider.Endpoint(),
		RedirectURL: "http://localhost:8081/auth/callback",
		Scopes:      []string{oidc.ScopeOpenID, "profile", "email"},
	}

	return *oidcConfig, config
}

func main() {
	http.HandleFunc("/", redirectHandler)
	http.HandleFunc("/auth/callback", callbackHandler)

	log.Printf("To authenticate go to http://%s/", "localhost:8081")
	log.Fatal(http.ListenAndServe("localhost:8081", nil))
}

func redirectHandler(resp http.ResponseWriter, r *http.Request) {
	state := addStateCookie(resp)
	http.Redirect(resp, r, oauth2Config.AuthCodeURL(state), http.StatusFound)
}

func callbackHandler(resp http.ResponseWriter, req *http.Request) {
	err := checkStateAndExpireCookie(req, resp)

	if err != nil {
		redirectHandler(resp, req)
		return
	}

	tokenResponse, err := exchangeCode(req)

	if err != nil {
		http.Error(resp, "Failed to exchange code", http.StatusBadRequest)
		return
	}

	idToken, err := validateIDToken(tokenResponse, req)

	if err != nil {
		http.Error(resp, "Failed to validate id_token", http.StatusUnauthorized)
		return
	}

	handleSuccessfulAuthentication(tokenResponse, *idToken, resp)
}

func addStateCookie(resp http.ResponseWriter) string {
	expire := time.Now().Add(1 * time.Minute)
	value := uuid.New().String()

	cookie := http.Cookie{
		Name:     "p_state",
		Value:    value,
		Expires:  expire,
		HttpOnly: true,
	}

	http.SetCookie(resp, &cookie)

	return value
}

func expireCookie(name string, resp http.ResponseWriter) {
	cookie := &http.Cookie{
		Name:     "p_state",
		Value:    "",
		MaxAge:   -1,
		HttpOnly: true,
	}

	http.SetCookie(resp, cookie)
}

func checkStateAndExpireCookie(req *http.Request, resp http.ResponseWriter) error {
	state, err := req.Cookie("p_state")

	expireCookie("p_state", resp)

	if err != nil {
		return errors.New("state cookie not set")
	}

	if req.URL.Query().Get("state") != state.Value {
		return errors.New("invalid state")
	}

	return nil
}

func exchangeCode(req *http.Request) (*oauth2.Token, error) {
	httpClient := &http.Client{Timeout: 2 * time.Second}
	ctx := context.WithValue(req.Context(), oauth2.HTTPClient, httpClient)

	tokenResponse, err := oauth2Config.Exchange(ctx, req.URL.Query().Get("code"))

	if err != nil {
		return nil, err
	}

	return tokenResponse, nil
}

func validateIDToken(tokenResponse *oauth2.Token, req *http.Request) (*oidc.IDToken, error) {
	rawIDToken, ok := tokenResponse.Extra("id_token").(string)

	if !ok {
		return nil, errors.New("id_token is not in the token response")
	}

	idToken, err := idTokenVerifier.Verify(req.Context(), rawIDToken)

	if err != nil {
		return nil, err
	}

	return idToken, nil
}

func handleSuccessfulAuthentication(tokenResponse *oauth2.Token, idToken oidc.IDToken, resp http.ResponseWriter) {
	payload := struct {
		TokenResponse *oauth2.Token
		IDToken       *json.RawMessage
	}{tokenResponse, new(json.RawMessage)}

	if err := idToken.Claims(&payload.IDToken); err != nil {
		return
	}

	data, err := json.MarshalIndent(&payload, "", "    ")

	if err != nil {
		http.Error(resp, err.Error(), http.StatusInternalServerError)
		return
	}

	resp.Write(data)
}


// curl --location --request POST 'http://localhost:8080/realms/myrealm/protocol/openid-connect/token' \
// --header 'Content-Type: application/x-www-form-urlencoded' \
// --header 'Authorization: Basic base64(my_client:hXhSPe0h13yWe7bvOEOYqzsBgzE9J0ER)' \
// --data-urlencode 'grant_type=client_credentials'
