package ory

import (
	"net/http"

	jwtmiddleware "github.com/auth0/go-jwt-middleware"
	"github.com/dgrijalva/jwt-go"
	"github.com/ory/x/jwksx"
	"github.com/urfave/negroni"
)

type Middleware struct {
	wku string
	jm  *jwtmiddleware.JWTMiddleware
}

type middlewareOptions struct {
	Debug        bool
	ErrorHandler func(w http.ResponseWriter, r *http.Request, err string)
}

type MiddlewareOption func(*middlewareOptions)

func MiddlewareWithErrorHandler(errorHandler func(w http.ResponseWriter, r *http.Request, err string)) MiddlewareOption {
	return func(o *middlewareOptions) {
		o.ErrorHandler = errorHandler
	}
}

func MiddlewareDebugEnabled() MiddlewareOption {
	return func(o *middlewareOptions) {
		o.Debug = true
	}
}

func NewMiddleware(
	wellKnownURL string,
	opts ...MiddlewareOption,
) *Middleware {
	var c = new(middlewareOptions)

	for _, o := range opts {
		o(c)
	}

	jc := jwksx.NewFetcher(wellKnownURL)
	return &Middleware{
		wku: wellKnownURL,
		jm: jwtmiddleware.New(jwtmiddleware.Options{
			ValidationKeyGetter: func(token *jwt.Token) (interface{}, error) {
				k, err := jc.GetKey(token.Header["kid"].(string))
				if err != nil {
					return nil, err
				}
				return k.Key, nil
			},
			ErrorHandler:  c.ErrorHandler,
			SigningMethod: jwt.SigningMethodRS256,
			UserProperty:  identityContextKey,
			CredentialsOptional: false,
		}),
	}
}

func (h *Middleware) NegroniHandler() negroni.Handler {
	return negroni.HandlerFunc(h.jm.HandlerWithNext)
}
