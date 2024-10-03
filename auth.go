package main

import (
	"context"
	"errors"
	"log"
	"net/url"
	"time"

	"github.com/auth0/go-jwt-middleware/v2/jwks"
	"github.com/auth0/go-jwt-middleware/v2/validator"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type Authenticator struct {
	*oidc.Provider
	oauth2.Config
	AuthCredentials
}

func NewAuthenticator(ac *AuthCredentials) (*Authenticator, error) {
	provider, err := oidc.NewProvider(
		context.Background(),
		ac.URL,
	)
	if err != nil {
		return nil, err
	}

	conf := oauth2.Config{
		ClientID:     ac.ClientID,
		ClientSecret: ac.ClientSecret,
		RedirectURL:  ac.RedirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile"},
	}

	return &Authenticator{
		Provider:        provider,
		Config:          conf,
		AuthCredentials: *ac,
	}, nil
}

func (a *Authenticator) VerifyIDToken(ctx context.Context, token *oauth2.Token) (*oidc.IDToken, error) {
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, errors.New("no id_token field in oauth2 token")
	}

	oidcConfig := &oidc.Config{
		ClientID: a.ClientID,
	}

	return a.Verifier(oidcConfig).Verify(ctx, rawIDToken)
}

func (auth *Authenticator) CheckAuth(token string) (bool, error) {
	url, err := url.Parse(auth.URL)
	if err != nil {
		log.Fatalf("Failed to parse the URL: %v", err)
	}

	provider := jwks.NewCachingProvider(url, 5*time.Minute)

	jwtValidator, err := validator.New(
		provider.KeyFunc,
		validator.RS256,
		auth.URL,
		[]string{auth.Audience},
	)

	if err != nil {
		log.Fatalf("Failed to create the jwt validator: %v", err)
	}

	_, err = jwtValidator.ValidateToken(context.Background(), token)
	if err != nil {
		return false, err
	}

	return true, nil
}
