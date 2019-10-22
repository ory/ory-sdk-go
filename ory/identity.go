package ory

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/dgrijalva/jwt-go"
)

const identityContextKey = "identity"

type Session struct {
	Identity Identity
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

	claims, ok := raw.(*jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf(`expected context key "%s" to transport value of type *jwt.MapClaims but got type: %t`, identityContextKey, raw)
	}

	var buff bytes.Buffer
	if err := json.NewEncoder(&buff).Encode(claims); err != nil {
		return nil, fmt.Errorf("unable to encode session data: %w", err)
	}
	if err := json.NewDecoder(&buff).Decode(&s); err != nil {
		return nil, fmt.Errorf("unable to decode session data: %w", err)
	}

	return &s, nil
}
