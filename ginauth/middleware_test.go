package ginauth

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ardynlabs/ardyncommon/auth"
	"github.com/gin-gonic/gin"
)

type verifierFunc func(string) (auth.Claims, error)

func (function verifierFunc) Verify(token string) (auth.Claims, error) { return function(token) }

func TestExtractBearerNeverPanicsOnMalformedHeaders(t *testing.T) {
	t.Parallel()
	for _, header := range []string{"", "Basic abc", "Bearer", "Bearer    ", "x", "Bearer a b"} {
		if _, err := ExtractBearer(header); !errors.Is(err, ErrInvalidBearerHeader) {
			t.Errorf("ExtractBearer(%q) error = %v, want ErrInvalidBearerHeader", header, err)
		}
	}
	token, err := ExtractBearer("bearer token")
	if err != nil || token != "token" {
		t.Fatalf("ExtractBearer() = %q, %v", token, err)
	}
}

func TestMiddlewareAuthenticationAndAuthorizationStatuses(t *testing.T) {
	gin.SetMode(gin.TestMode)
	middleware := New(verifierFunc(func(token string) (auth.Claims, error) {
		if token != "valid" {
			return auth.Claims{}, errors.New("invalid")
		}
		return auth.Claims{Subject: auth.Subject{UserID: "user-1", Roles: []string{"reader"}}}, nil
	}))

	tests := []struct {
		name   string
		header string
		status int
	}{
		{name: "missing", status: http.StatusUnauthorized},
		{name: "malformed", header: "Basic abc", status: http.StatusUnauthorized},
		{name: "invalid", header: "Bearer invalid", status: http.StatusUnauthorized},
		{name: "forbidden", header: "Bearer valid", status: http.StatusForbidden},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			router := gin.New()
			router.GET("/protected", middleware.RequireAnyRole("admin"), func(context *gin.Context) {
				context.Status(http.StatusNoContent)
			})
			request := httptest.NewRequest(http.MethodGet, "/protected", nil)
			request.Header.Set("Authorization", test.header)
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code != test.status {
				t.Fatalf("status = %d, want %d", response.Code, test.status)
			}
		})
	}
}

func TestMiddlewareStoresClaimsSafely(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/protected", New(verifierFunc(func(string) (auth.Claims, error) {
		return auth.Claims{Subject: auth.Subject{UserID: "user-1", Roles: []string{"reader"}}}, nil
	})).RequireAuthentication(), func(context *gin.Context) {
		claims, ok := ClaimsFromContext(context)
		if !ok || claims.UserID != "user-1" {
			context.Status(http.StatusInternalServerError)
			return
		}
		context.Status(http.StatusNoContent)
	})
	request := httptest.NewRequest(http.MethodGet, "/protected", nil)
	request.Header.Set("Authorization", "Bearer valid")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusNoContent)
	}
}
