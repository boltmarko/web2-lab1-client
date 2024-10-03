package main

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/google/uuid"

	"github.com/joho/godotenv"
)

type Config struct {
	ApiUrl   string
	ApiToken string
	Auth     *Authenticator
}

type Credentials struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Audience     string `json:"audience"`
	URL          string `json:"url"`
}

type APICredentials Credentials

type AuthCredentials struct {
	Credentials
	RedirectURL string `json:"redirect_url"`
}

type TicketData struct {
	ID        uuid.UUID
	Vatin     string
	FirstName string
	LastName  string
	CreatedAt time.Time
}

type HomeData struct {
	TotalTickets int `json:"total_tickets"`
}

func getApiToken(ac APICredentials) (string, error) {
	payload, err := json.Marshal(map[string]string{
		"client_id":     ac.ClientID,
		"client_secret": ac.ClientSecret,
		"audience":      ac.Audience,
		"grant_type":    "client_credentials",
	})
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", ac.URL, bytes.NewBuffer(payload))
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", err
	}

	var data map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&data)
	if err != nil {
		return "", err
	}

	token, ok := data["access_token"].(string)
	if !ok {
		return "", err
	}

	return token, nil
}

func getApiCredentials() APICredentials {
	authURL := "https://" + os.Getenv("AUTH0_DOMAIN") + "/oauth/token"
	clientID := os.Getenv("API_CLIENT_ID")
	clientSecret := os.Getenv("API_CLIENT_SECRET")
	audience := os.Getenv("API_AUDIENCE")
	if authURL == "" || clientSecret == "" || clientID == "" || audience == "" {
		log.Fatal("API_CLIENT_SECRET and API_CLIENT_ID are required")
	}

	return APICredentials{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Audience:     audience,
		URL:          authURL,
	}
}

func getAuthCredentials() AuthCredentials {
	authURL := "https://" + os.Getenv("AUTH0_DOMAIN") + "/"
	clientID := os.Getenv("OIDC_CLIENT_ID")
	clientSecret := os.Getenv("OIDC_CLIENT_SECRET")
	audience := os.Getenv("OIDC_AUDIENCE")

	externalURL := os.Getenv("RENDER_EXTERNAL_URL")
	if externalURL == "" {
		externalURL = "http://localhost:8081"
	}

	if authURL == "" || clientSecret == "" || clientID == "" {
		log.Fatal("OIDC_CLIENT_SECRET, OIDC_CLIENT_ID and OIDC_REDIRECT_URI are required")
	}

	redirectURL := externalURL + "/callback"

	return AuthCredentials{
		Credentials: Credentials{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			URL:          authURL,
			Audience:     audience,
		},
		RedirectURL: redirectURL,
	}
}

func main() {
	if err := godotenv.Load(); err != nil {
		log.Println(".env file not found, proceeding...")
	}

	apiCredentials := getApiCredentials()

	apiToken, err := getApiToken(apiCredentials)
	if err != nil {
		log.Fatal(err)
	}

	authCredentials := getAuthCredentials()

	auth, err := NewAuthenticator(&authCredentials)
	if err != nil {
		log.Fatal(err)
	}

	apiURL := os.Getenv("API_URL")
	if apiURL == "" {
		apiURL = "http://localhost:8080"
	}

	config := Config{
		ApiUrl:   apiURL,
		ApiToken: apiToken,
		Auth:     auth,
	}

	router := http.NewServeMux()

	router.HandleFunc("GET /ticket/{id}", handleTicket(&config))
	router.HandleFunc("GET /{$}", handleHome(&config))

	router.HandleFunc("GET /login", handleLogin(&config))
	router.HandleFunc("GET /callback", handleCallback(&config))

	port := os.Getenv("PORT")
	if port == "" {
		port = "8081"
	}

	log.Println("Server started on :" + port)
	log.Fatal(http.ListenAndServe(":"+port, router))
}
