package kissauth

import (
	"testing"
	"time"
)

// TestGenerateAndValidateJWT tests the GenerateJWT and ValidateJWT methods.
func TestGenerateAndValidateJWT(t *testing.T) {
	// Define test cases
	tests := []struct {
		name           string
		claims         any
		expiration     *time.Time
		issuer         *string
		jwtSecret      string
		validateSecret string
		wantErr        bool
		validateErr    bool
	}{
		{
			name:           "Happy Path - Valid JWT",
			claims:         map[string]interface{}{"userID": 123, "username": "john_doe"},
			expiration:     nil, // Use default expiration
			issuer:         nil, // Use default issuer
			jwtSecret:      "test-secret",
			validateSecret: "test-secret",
			wantErr:        false,
			validateErr:    false,
		},
		{
			name:           "Invalid Signing Method",
			claims:         map[string]interface{}{"userID": 123},
			expiration:     nil,
			issuer:         nil,
			jwtSecret:      "test-secret",
			validateSecret: "wrong-secret",
			wantErr:        false,
			validateErr:    true,
		},
		{
			name:           "Expired Token",
			claims:         map[string]interface{}{"userID": 123},
			expiration:     func() *time.Time { t := time.Now().Add(-time.Hour); return &t }(), // Expired 1 hour ago
			issuer:         nil,
			jwtSecret:      "test-secret",
			validateSecret: "test-secret",
			wantErr:        false,
			validateErr:    true,
		},
		{
			name:           "Malformed Token",
			claims:         map[string]interface{}{"userID": 123},
			expiration:     nil,
			issuer:         nil,
			jwtSecret:      "test-secret",
			validateSecret: "test-secret",
			wantErr:        false,
			validateErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a new KissAuthClient
			client := &KissAuthClient{
				jwtSecret: tt.jwtSecret,
			}

			// Generate a JWT
			tokenString, err := client.GenerateJWT(tt.claims, tt.expiration, tt.issuer)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateJWT() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// Skip validation for malformed token test case
			if tt.name == "Malformed Token" {
				tokenString = "malformed.token.string"
			}

			// Validate the JWT
			client.jwtSecret = tt.validateSecret // Override secret for validation
			claims, err := client.ValidateJWT(tokenString)
			if (err != nil) != tt.validateErr {
				t.Errorf("ValidateJWT() error = %v, validateErr %v", err, tt.validateErr)
				return
			}

			// Check claims if validation succeeded
			if !tt.validateErr {
				if claims == nil {
					t.Error("ValidateJWT() claims should not be nil")
				} else {
					// Verify custom claims
					customClaims := claims.(*JWTClaims).CustomClaims
					if customClaims == nil {
						t.Error("ValidateJWT() custom claims should not be nil")
					}
				}
			}
		})
	}
}
