package ory

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	jwtmiddleware "github.com/auth0/go-jwt-middleware"
	"github.com/dgrijalva/jwt-go"
	"github.com/ory/x/jwksx"
	"github.com/urfave/negroni"
)

type Middleware struct {
	o   *middlewareOptions
	wku string
	jm  *jwtmiddleware.JWTMiddleware
}

type middlewareOptions struct {
	Debug        bool
	ErrorHandler func(w http.ResponseWriter, r *http.Request, err string)
	ExcludePaths []string
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

func MiddlewareExcludePaths(paths ...string) MiddlewareOption {
	return func(o *middlewareOptions) {
		o.ExcludePaths = append(o.ExcludePaths, paths...)
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
		o:   c,
		wku: wellKnownURL,
		jm: jwtmiddleware.New(jwtmiddleware.Options{
			ValidationKeyGetter: func(token *jwt.Token) (interface{}, error) {
				if raw, ok := token.Header["kid"]; !ok {
					return nil, errors.New(`jwt from authorization HTTP header is missing value for "kid" in token header`)
				} else if kid, ok := raw.(string); !ok {
					return nil, fmt.Errorf(`jwt from authorization HTTP header is expecting string value for "kid" in tokenWithoutKid header but got: %T`, raw)
				} else if k, err := jc.GetKey(kid); err != nil {
					return nil, err
				} else {
					return k.Key, nil
				}
			},
			ErrorHandler:        c.ErrorHandler,
			SigningMethod:       jwt.SigningMethodRS256,
			UserProperty:        identityContextKey,
			CredentialsOptional: false,
		}),
	}
}

func (h *Middleware) NegroniHandler() negroni.Handler {
	return negroni.HandlerFunc(func(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
		for _, excluded := range h.o.ExcludePaths {
			if strings.HasPrefix(r.URL.Path, excluded) {
				next(w, r)
				return
			}
		}

		h.jm.HandlerWithNext(w, r, next)
	})
}
