package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/LevisThors/kissauth"
	"github.com/joho/godotenv"
)

// Define your custom user struct
type User struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

func main() {
	if err := godotenv.Load("./example/.env"); err != nil {
		log.Fatal("Error loading .env file")
	}

	// Configuration
	config := kissauth.KissAuthClientConfig{
		GoogleClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		GoogleClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		GoogleRedirectURL:  os.Getenv("GOOGLE_REDIRECT_URL"),
		GoogleScopes:       []string{"https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email"},
		Verifier:           os.Getenv("VERIFIER"),
		JWTSecret:          os.Getenv("JWT_SECRET"),
	}

	// Create a new client
	client := kissauth.New(config)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Welcome to the KissAuth example! <a href='/auth/google/redirect'>Login with Google</a>")
	})

	// Handle Google OAuth2 login
	http.HandleFunc("/auth/google/redirect", func(w http.ResponseWriter, r *http.Request) {
		state := "I-want-this-data-in-callback"
		redirectURL := client.GetGoogleRedirectURL(state)

		log.Println("User is being redirected to:", redirectURL)

		http.Redirect(w, r, redirectURL, http.StatusFound)
	})

	// Handle Google OAuth2 callback
	http.HandleFunc("/auth/google/callback", func(w http.ResponseWriter, r *http.Request) {
		// Extract the authorization code from the query parameters
		code := r.URL.Query().Get("code")
		if code == "" {
			http.Error(w, "Authorization code not found", http.StatusBadRequest)
			return
		}

		// Extract state from the query parameters
		veryImportantData := r.URL.Query().Get("state")
		if code == "" {
			http.Error(w, "Authorization code not found", http.StatusBadRequest)
			return
		}

		log.Println("Very important data:", veryImportantData)

		// Define a variable to hold the user information
		var user User

		// Exchange the authorization code for user info
		err := client.ExchangeGoogleCode(r.Context(), code, &user)
		if err != nil {
			http.Error(w, fmt.Sprintf("Error exchanging code: %v", err), http.StatusInternalServerError)
			return
		}

		jwtToken, err := client.GenerateJWT(user, nil, nil)
		if err != nil {
			http.Error(w, fmt.Sprintf("Error generating JWT: %v", err), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"user": user,
			"jwt":  jwtToken,
		})
	})

	fmt.Println("Server is running on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
