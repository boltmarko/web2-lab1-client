package main

import (
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/oauth2"

	"github.com/joho/godotenv"
)

type APICredentials struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Audience     string `json:"audience"`
	URL          string `json:"url"`
}

type AuthCredentials struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Audience     string `json:"audience"`
	URL          string `json:"url"`
	RedirectURL  string `json:"redirect_url"`
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

func createHomeHandler(token string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		apiURL := os.Getenv("RENDER_EXTERNAL_URL")
		if apiURL == "" {
			apiURL = "http://localhost:8080"
		}

		req, err := http.NewRequest("GET", apiURL+"/api/tickets/total", nil)

		req.Header.Set("Authorization", "Bearer "+token)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			log.Println(err)
			http.Error(w, "Error fetching total tickets", http.StatusInternalServerError)
			return
		}

		if resp.StatusCode != http.StatusOK {
			log.Println(resp.StatusCode)
			http.Error(w, "Error fetching total tickets", http.StatusInternalServerError)
			return
		}
		var homeData HomeData
		err = json.NewDecoder(resp.Body).Decode(&homeData)
		if err != nil {
			log.Println(err)
			http.Error(w, "Error parsing total tickets", http.StatusInternalServerError)
			return
		}

		t, err := template.ParseFiles("templates/home.html")
		if err != nil {
			log.Println(err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		t.Execute(w, homeData)
	}
}

func createTicketHandler(token string, auth *Authenticator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// get access token from cookie
		cookie, err := r.Cookie("token")
		if err != nil {
			log.Println(err)
			http.Error(w, "Failed to authenticate", http.StatusUnauthorized)
			return
		}

		accessToken := cookie.Value

		_, err = auth.CheckAuth(accessToken)
		if err != nil {
			log.Println(err)
			http.Error(w, "Failed to authenticate", http.StatusUnauthorized)
			return
		}

		apiURL := os.Getenv("RENDER_EXTERNAL_URL")
		if apiURL == "" {
			apiURL = "http://localhost:8080"
		}

		id := r.PathValue("id")
		if id == "" {
			log.Println("Ticket ID is required")
			http.Error(w, "Ticket ID is required", http.StatusBadRequest)
			return
		}

		_, err = uuid.Parse(id)
		if err != nil {
			log.Println(err)
			http.Error(w, "Invalid ticket ID", http.StatusBadRequest)
			return
		}

		req, err := http.NewRequest("GET", apiURL+"/api/tickets/"+id, nil)

		req.Header.Set("Authorization", "Bearer "+token)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			log.Println(err)
			http.Error(w, "Error fetching ticket data", http.StatusInternalServerError)
			return
		}

		if resp.StatusCode != http.StatusOK {
			http.Error(w, "Error fetching ticket data", http.StatusInternalServerError)
			return
		}

		var ticket TicketData
		err = json.NewDecoder(resp.Body).Decode(&ticket)
		if err != nil {
			log.Println(err)
			http.Error(w, "Error parsing ticket data", http.StatusInternalServerError)
			return
		}

		t, err := template.ParseFiles("templates/ticket.html")
		if err != nil {
			log.Println(err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		t.Execute(w, ticket)

	}
}

func createLoginHandler(a *Authenticator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var audParam oauth2.AuthCodeOption = oauth2.SetAuthURLParam("audience", a.ac.Audience)
		http.Redirect(w, r, a.AuthCodeURL("state", audParam), http.StatusTemporaryRedirect)
	}
}

func createCallbackHandler(a *Authenticator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		oauth2Token, err := a.Exchange(ctx, r.URL.Query().Get("code"))
		if err != nil {
			log.Println(err)
			http.Error(w, "Failed to exchange token", http.StatusInternalServerError)
			return
		}

		_, err = a.VerifyIDToken(ctx, oauth2Token)
		if err != nil {
			log.Println(err)
			http.Error(w, "Failed to verify ID token", http.StatusInternalServerError)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:    "token",
			Value:   oauth2Token.AccessToken,
			Expires: time.Now().Add(24 * time.Hour),
		})

		http.Redirect(w, r, "/", http.StatusFound)
	}
}

func authenticate(ac APICredentials) (string, error) {
	jsonPayload := `{"client_id":"` + ac.ClientID + `","client_secret":"` + ac.ClientSecret + `","audience":"` + ac.Audience + `","grant_type":"client_credentials"}`

	req, err := http.NewRequest("POST", ac.URL, strings.NewReader(jsonPayload))
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

func getAPICredentials() APICredentials {
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
		ClientID:     clientID,
		ClientSecret: clientSecret,
		URL:          authURL,
		Audience:     audience,
		RedirectURL:  redirectURL,
	}
}

func main() {
	if err := godotenv.Load(); err != nil {
		log.Fatal("Error loading .env file")
	}

	apiCredentials := getAPICredentials()

	token, err := authenticate(apiCredentials)
	if err != nil {
		log.Fatal(err)
	}

	authCredentials := getAuthCredentials()

	auth, err := NewAuthenticator(&authCredentials)
	if err != nil {
		log.Fatal(err)
	}

	router := http.NewServeMux()

	router.HandleFunc("GET /ticket/{id}", createTicketHandler(token, auth))
	router.HandleFunc("GET /{$}", createHomeHandler(token))

	router.HandleFunc("GET /login", createLoginHandler(auth))
	router.HandleFunc("GET /callback", createCallbackHandler(auth))

	port := os.Getenv("PORT")
	if port == "" {
		port = "8081"
	}

	log.Println("Server started on :" + port)
	log.Fatal(http.ListenAndServe(":"+port, router))
}
