package kissauth

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

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

// Unwraps custom claims which you put in JWT token and returns them.
// It returns ErrInvalidType if CustomClaims can't be casted to T
func UnwrapJWTClaims[T any](claims any) (T, error) {
	customClaims, ok := claims.(JWTClaims).CustomClaims.(T)
	if !ok {
		var emptyValue T
		return emptyValue, ErrInvalidType
	}

	return customClaims, nil
}
