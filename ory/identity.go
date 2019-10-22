package ory

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/dgrijalva/jwt-go"
)

const identityContextKey = "identity"

type Session struct {
	Identity Identity `json:"identity"`
}

type Identity struct {
	ID string `json:"id"`
}

func SessionFromRequest(r *http.Request) (*Session, error) {
	var s Session
	raw := r.Context().Value(identityContextKey)
	if raw == nil {
		return nil, fmt.Errorf(`expected context key "%s" to transport a value but received nil`, identityContextKey)
	}

	token, ok := raw.(*jwt.Token)
	if !ok {
		return nil, fmt.Errorf(`expected context key "%s" to transport value of type *jwt.MapClaims but got type: %T`, identityContextKey, raw)
	}

	var buff bytes.Buffer
	if err := json.NewEncoder(&buff).Encode(token.Claims); err != nil {
		return nil, fmt.Errorf("unable to encode session data: %w", err)
	}
	if err := json.NewDecoder(&buff).Decode(&s); err != nil {
		return nil, fmt.Errorf("unable to decode session data: %w", err)
	}

	if s.Identity.ID == "" {
		return nil,  errors.New("expected identity.id to be set but no value was set")
	}

	return &s, nil
}
