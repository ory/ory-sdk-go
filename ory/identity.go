package ory

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/dgrijalva/jwt-go"
)

const IdentityContextKey = "identity"

type Session struct {
	Identity Identity `json:"identity"`
}

type Identity struct {
	ID string `json:"id"`
}

func SessionFromRequest(r *http.Request) (*Session, error) {
	raw := r.Context().Value(IdentityContextKey)
	if raw == nil {
		return nil, fmt.Errorf(`expected context key "%s" to transport a value but received nil`, IdentityContextKey)
	}

	token, ok := raw.(*jwt.Token)
	if !ok {
		return nil, fmt.Errorf(`expected context key "%s" to transport value of type *jwt.MapClaims but got type: %T`, IdentityContextKey, raw)
	}

	var buff bytes.Buffer
	var c jwt.StandardClaims
	if err := json.NewEncoder(&buff).Encode(token.Claims); err != nil {
		return nil, fmt.Errorf("unable to encode session data: %w", err)
	}
	if err := json.NewDecoder(&buff).Decode(&c); err != nil {
		return nil, fmt.Errorf("unable to decode session data: %w", err)
	}

	if c.Subject == "" {
		return nil, errors.New("expected subject claim to be set but no value was set")
	}

	return &Session{
		Identity: Identity{
			ID: c.Subject,
		},
	}, nil
}
