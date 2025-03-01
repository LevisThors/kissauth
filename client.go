// Package kissauth provides a simple and extensible authentication solution
// for Go applications. It supports OAuth2 with Google and JWT (JSON Web Tokens)
// for secure user authentication and authorization.
package kissauth

import (
	"errors"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

var (
	// ErrEmptyOAuthCode is returned when an empty OAuth2 code is provided
	// during the token exchange process.
	ErrEmptyOAuthCode = errors.New("kissauth: empty code was passed to oauth exchange")

	// ErrInvalidJWT is returned when an invalid or malformed JWT is provided
	// during token validation.
	ErrInvalidJWT = errors.New("kissauth: invalid token passed to jwt validation")

	// ErrInvalidType is returned when type passed to UnwrapJWT is not the same type
	// as CustomClaims (which you used for generating JWT token).
	ErrInvalidType = errors.New("kissauth: can't cast type to jwt custom claims")
)

// KissAuthClientConfig holds the configuration required to initialize
// the KissAuthClient. It includes OAuth2 client details and JWT secret
type KissAuthClientConfig struct {
	GoogleClientID     string   // Google OAuth2 Client ID
	GoogleClientSecret string   // Google OAuth2 Client Secret
	GoogleRedirectURL  string   // Google OAuth2 Redirect URL
	GoogleScopes       []string // Google OAuth2 Scopes
	Verifier           string   // OAuth2 PKCE verifier
	JWTSecret          string   // Secret key for signing and validating JWTs
}

// KissAuthClient is the main client for handling authentication operations.
// It provides methods for OAuth2 code exchange, JWT generation, and validation.
type KissAuthClient struct {
	oauthConfig *oauth2.Config // OAuth2 configuration
	verifier    string         // OAuth2 PKCE verifier
	jwtSecret   string         // Secret key for JWTs
}

// JWTClaims represents the claims included in a JWT. It supports custom claims
// along with standard registered claims like expiration, issuer, etc.
type JWTClaims struct {
	CustomClaims any // Custom claims to be included in the JWT
	jwt.RegisteredClaims
}

// New initializes and returns a new KissAuthClient with the provided configuration.
// It sets up the OAuth2 configuration using Google as the provider.
func New(conf KissAuthClientConfig) *KissAuthClient {
	return &KissAuthClient{
		oauthConfig: &oauth2.Config{
			ClientID:     conf.GoogleClientID,
			ClientSecret: conf.GoogleClientSecret,
			RedirectURL:  conf.GoogleRedirectURL,
			Scopes:       conf.GoogleScopes,
			Endpoint:     google.Endpoint,
		},
		verifier:  conf.Verifier,
		jwtSecret: conf.JWTSecret,
	}
}
