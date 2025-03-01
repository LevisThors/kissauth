package kissauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"golang.org/x/oauth2"
)

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
