// Package ginauth adapts auth.Verifier to Gin. Generic JWT code remains in
// package auth so non-HTTP consumers do not depend on Gin.
package ginauth

import (
	"errors"
	"net/http"
	"strings"

	"github.com/ardynlabs/ardyncommon/api"
	"github.com/ardynlabs/ardyncommon/auth"
	"github.com/gin-gonic/gin"
)

const (
	ClaimsContextKey = "ardyn.auth.claims"
	UserIDContextKey = "ardyn.auth.user_id"
	RolesContextKey  = "ardyn.auth.roles"
)

var ErrInvalidBearerHeader = errors.New("authorization header must contain a Bearer token")

// Middleware creates Gin authentication and role-authorization handlers.
type Middleware struct {
	verifier auth.Verifier
}

func New(verifier auth.Verifier) *Middleware {
	return &Middleware{verifier: verifier}
}

// RequireAuthentication rejects missing or invalid credentials with 401.
func (middleware *Middleware) RequireAuthentication() gin.HandlerFunc {
	return func(context *gin.Context) {
		middleware.authenticate(context)
	}
}

// RequireAnyRole authenticates then requires at least one of roles. A valid
// identity that lacks permission receives 403, never 401.
func (middleware *Middleware) RequireAnyRole(roles ...string) gin.HandlerFunc {
	required := make(map[string]struct{}, len(roles))
	for _, role := range roles {
		if role != "" {
			required[role] = struct{}{}
		}
	}

	return func(context *gin.Context) {
		claims, ok := middleware.authenticate(context)
		if !ok {
			return
		}
		for _, role := range claims.Roles {
			if _, permitted := required[role]; permitted {
				return
			}
		}
		abortProblem(context, http.StatusForbidden, "Forbidden", "You do not have permission to perform this action.")
	}
}

func (middleware *Middleware) authenticate(context *gin.Context) (auth.Claims, bool) {
	if middleware == nil || middleware.verifier == nil {
		abortProblem(context, http.StatusUnauthorized, "Unauthorized", "Valid authentication credentials are required.")
		return auth.Claims{}, false
	}
	rawToken, err := ExtractBearer(context.GetHeader("Authorization"))
	if err != nil {
		abortProblem(context, http.StatusUnauthorized, "Unauthorized", "Valid authentication credentials are required.")
		return auth.Claims{}, false
	}
	claims, err := middleware.verifier.Verify(rawToken)
	if err != nil {
		abortProblem(context, http.StatusUnauthorized, "Unauthorized", "Valid authentication credentials are required.")
		return auth.Claims{}, false
	}
	context.Set(ClaimsContextKey, claims)
	context.Set(UserIDContextKey, claims.UserID)
	context.Set(RolesContextKey, append([]string(nil), claims.Roles...))
	return claims, true
}

func abortProblem(context *gin.Context, status int, title, detail string) {
	context.Header("Content-Type", "application/problem+json")
	context.AbortWithStatusJSON(status, api.NewProblem(status, title, detail))
}

// ExtractBearer safely parses an Authorization header. It deliberately uses
// Fields instead of slicing so malformed or short headers cannot panic.
func ExtractBearer(header string) (string, error) {
	parts := strings.Fields(header)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || parts[1] == "" {
		return "", ErrInvalidBearerHeader
	}
	return parts[1], nil
}

// ClaimsFromContext retrieves claims safely for handlers that ran after this
// middleware. It never assumes a context key's type.
func ClaimsFromContext(context *gin.Context) (auth.Claims, bool) {
	if context == nil {
		return auth.Claims{}, false
	}
	value, ok := context.Get(ClaimsContextKey)
	if !ok {
		return auth.Claims{}, false
	}
	claims, ok := value.(auth.Claims)
	return claims, ok
}
