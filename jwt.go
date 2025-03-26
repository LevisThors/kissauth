package kissauth

import (
	"encoding/json"
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

// Unmarshals claims and parses it to result, result should
// be the reference of type, which claims can unmap to
// e.g. if you used UserType in GenerateJWT, your UnmarshalJWTClaims
// will be:
// var user UserType
// err := unmarshalJWTClaims(claims, &user)
func UnmarshalJWTClaims(claims any, result any) error {
	jwtClaims, ok := claims.(*JWTClaims)
	if !ok {
		return ErrInvalidType
	}

	switch v := jwtClaims.CustomClaims.(type) {
	case map[string]interface{}:
		jsonData, err := json.Marshal(v)
		if err != nil {
			return fmt.Errorf("marshal error: %w", err)
		}

		if err := json.Unmarshal(jsonData, result); err != nil {
			return fmt.Errorf("unmarshal error: %w", err)
		}
		return nil
	default:
		return ErrInvalidType
	}
}
