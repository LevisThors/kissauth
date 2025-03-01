# KissAuth

KissAuth is a Go package designed to make authentication operations extremely simple. It provides seamless integration with OAuth2 providers (starting with Google) and supports JWT (JSON Web Tokens) for secure user authentication and authorization. The package is designed to be extensible, allowing you to easily add support for additional OAuth providers in the future.

## Features

- **Google OAuth2 Integration**: Easily authenticate users with Google OAuth2.
- **JWT Support**: Generate and validate JSON Web Tokens for secure user sessions.
- **Extensible**: Designed to support additional OAuth providers (e.g., Facebook, GitHub) in the future.
- **Simple API**: Minimal setup and straightforward methods for handling authentication.

## Installation

To use KissAuth in your Go project, run the following command:

```bash
go get github.com/LevisThors/kissauth
```

# Usage

## 1. Setting up KissAuth

First step is to create **KissAuthClient** with `New` method:

```go
package main

import (
	"context"
	"fmt"
	"time"

	"github.com/LevisThors/kissauth"
)

func main() {
	config := kissauth.KissAuthClientConfig{
		GoogleClientID:     "your-google-client-id",
		GoogleClientSecret: "your-google-client-secret",
		GoogleRedirectURL:  "http://localhost:8080/auth/callback",
		GoogleScopes:       []string{"https://www.googleapis.com/auth/userinfo.profile"},
		Verifier:          "your-pkce-verifier",
		JWTSecret:         "your-jwt-secret-key",
	}

	client := kissauth.New(config)
}
```

## 2. Get redirect url from provider

Use the `GetGoogleRedirectURL` method to generate the URL for redirecting users to Google's OAuth2 consent screen:

```go
    func main() {
        // ... (client setup as above)

        state := "state-that-will-persist-during-auth"
        redirectURL := client.GetGoogleRedirectURL(state)
        fmt.Println("Redirect URL:", redirectURL)
    }
```

## 3. Handling the OAuth Callback

After the user authenticates with Google, they will be redirected back to your application with an authorization code. Use the `ExchangeGoogleCode` method to exchange the code for a token and retrieve user information. The `ExchangeGoogleCode` method accepts a pointer to your `User` struct, where the user information will be decoded.

### Example

```go
type User struct {
    Name string `json:"name"`
    Email string `json:"email"`
}

func main() {
    // ... (client setup as above)

    // The authorization code returned after the redirect as a URL parameter
    code := "authorization-code-from-provider"
    ctx := context.Background()

    // Define a variable to hold the user information
    var user User

    // Call ExchangeGoogleCode with a pointer to the user struct
    err := client.ExchangeGoogleCode(ctx, code, &user)
    if err != nil {
        fmt.Println("Error exchanging code:", err)
        return
    }

    fmt.Println("User info:", user)
}
```

## 4. Generating JWT token

Once you have the user information, you can generate a JWT for the user session with `GenerateJWT` method:

```go
   func main() {
        // ... (client setup as above)

        claims := map[string]interface{}{
            "userID":   123,
            "username": "john_doe",
        }

        token, err := client.GenerateJWT(claims, nil, nil) // expiration and issuer are optional parameters
        if err != nil {
            fmt.Println("Error generating JWT:", err)
            return
        }

        fmt.Println("Generated JWT:", token)
    }
```

## 5. Validating JWT token

To validate a JWT and extract its claims, use the `ValidateJWT` method:

```go
   func main() {
       // ... (client setup as above)

        tokenString := "your-jwt-token"

        claims, err := client.ValidateJWT(tokenString)
        if err != nil {
            fmt.Println("Error validating JWT:", err)
            return
        }

        fmt.Println("JWT claims:", claims)
    }
```

## Configuration

The `KissAuthClientConfig` struct is used to configure the `KissAuthClient`. Here are the fields:

| Field                | Description                                                                  |
| -------------------- | ---------------------------------------------------------------------------- |
| `GoogleClientID`     | Your Google OAuth2 Client ID.                                                |
| `GoogleClientSecret` | Your Google OAuth2 Client Secret.                                            |
| `GoogleRedirectURL`  | The URL where Google will redirect the user after authentication.            |
| `GoogleScopes`       | The OAuth2 scopes to request from Google (e.g., `userinfo.profile`).         |
| `Verifier`           | The PKCE verifier for enhanced security.                                     |
| `JWTSecret`          | The secret key used to sign and validate JWTs.                               |
| `UserEntity`         | A struct or map to store user information retrieved from the OAuth provider. |
