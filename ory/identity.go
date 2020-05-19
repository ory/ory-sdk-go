package ory

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gofrs/uuid"
	"github.com/pkg/errors"

	"github.com/dgrijalva/jwt-go"
)

const IdentityContextKey = "identity"

type Session struct {
	Identity Identity `json:"identity"`
}

type Identity struct {
	ID uuid.UUID `json:"id"`
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

	userID, err := uuid.FromString(c.Subject)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return &Session{
		Identity: Identity{
			ID: userID,
		},
	}, nil
}
