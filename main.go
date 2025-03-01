// Package kissauth provides a simple and extensible authentication solution
// for Go applications. It supports OAuth2 with Google and JWT (JSON Web Tokens)
// for secure user authentication and authorization.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

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

// GetGoogleRedirectURL generates the Google OAuth2 redirect URL for initiating the
// authentication flow. It includes the state and PKCE verifier for security.
func (ac *KissAuthClient) GetGoogleRedirectURL(state string) string {
	return ac.oauthConfig.AuthCodeURL(
		state,
		oauth2.S256ChallengeOption(ac.verifier),
	)
}

// ExchangeGoogleCode exchanges the Google OAuth2 authorization code for a token and retrieves user information.
// The userEntity parameter is a pointer to the struct where the user information will be decoded.
func (ac *KissAuthClient) ExchangeGoogleCode(ctx context.Context, code string, userEntity any) error {
	if code == "" {
		return ErrEmptyOAuthCode
	}

	// Exchange the authorization code for a token
	token, err := ac.oauthConfig.Exchange(ctx, code, oauth2.VerifierOption(ac.verifier))
	if err != nil {
		return fmt.Errorf("kissauth: %w", err)
	}

	// Create an HTTP client using the retrieved token
	client := ac.oauthConfig.Client(ctx, token)

	// Fetch user information from Google
	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		return fmt.Errorf("kissauth: %w", err)
	}
	defer resp.Body.Close()

	// Check if the request was successful
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("kissauth: failed to fetch user info during google code exchange, status code %d", resp.StatusCode)
	}

	// Decode the user information into the provided user entity
	if err := json.NewDecoder(resp.Body).Decode(userEntity); err != nil {
		return fmt.Errorf("kissauth: %w", err)
	}

	return nil
}

// GenerateJWT creates a new JWT with the provided custom claims, expiration time,
// and issuer. If expiration or issuer is not provided, default values are used.
func (ac *KissAuthClient) GenerateJWT(claims any, expiration *time.Time, issuer *string) (string, error) {
	defaultExp := time.Now().Add(time.Hour * 24) // Default expiration: 24 hours
	defaultIssuer := ""                          // Default issuer: empty string

	if expiration == nil {
		expiration = &defaultExp
	}

	if issuer == nil {
		issuer = &defaultIssuer
	}

	// Create a new JWT with the provided claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, JWTClaims{
		CustomClaims: claims,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(*expiration),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    *issuer,
		},
	})

	// Sign the JWT with the secret key
	tokenString, err := token.SignedString([]byte(ac.jwtSecret))
	if err != nil {
		return "", fmt.Errorf("kissauth: %w", err)
	}

	return tokenString, nil
}

// ValidateJWT parses and validates a JWT. It returns the claims if the token
// is valid, otherwise it returns an error.
func (ac *KissAuthClient) ValidateJWT(tokenString string) (any, error) {
	token, err := jwt.ParseWithClaims(
		tokenString,
		&JWTClaims{},
		func(token *jwt.Token) (interface{}, error) {
			// Ensure the signing method is HMAC
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("kissauth: unexpected jwt signing method: %v", token.Header["alg"])
			}
			return []byte(ac.jwtSecret), nil
		},
	)
	if err != nil {
		return nil, fmt.Errorf("kissauth: failed to parse jwt token: %w", err)
	}

	// Verify the token and return the claims
	if claims, ok := token.Claims.(*JWTClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, ErrInvalidJWT
}
