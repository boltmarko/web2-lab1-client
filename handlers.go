package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"
	"golang.org/x/oauth2"
)

func handleHome(c *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		req, err := http.NewRequest("GET", c.ApiUrl+"/api/tickets/total", nil)

		req.Header.Set("Authorization", "Bearer "+c.ApiToken)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			log.Println(err)
			http.Error(w, fmt.Sprintf("Error fetching total tickets: %w", err), http.StatusInternalServerError)
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
			http.Error(w, fmt.Sprintf("Error parsing total tickets: %w", err), http.StatusInternalServerError)
			return
		}

		t, err := template.ParseFiles("templates/home.html")
		if err != nil {
			log.Println(err)
			http.Error(w, fmt.Sprintf("Internal server error: %w", err), http.StatusInternalServerError)
			return
		}

		t.Execute(w, homeData)
	}
}

func handleTicket(c *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("token")
		if err != nil {
			log.Println(err)
			http.Error(w, "Failed to authenticate", http.StatusUnauthorized)
			return
		}

		accessToken := cookie.Value

		_, err = c.Auth.CheckAuth(accessToken)
		if err != nil {
			log.Println(err)
			http.Error(w, "Failed to authenticate", http.StatusUnauthorized)
			return
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

		req, err := http.NewRequest("GET", c.ApiUrl+"/api/tickets/"+id, nil)

		req.Header.Set("Authorization", "Bearer "+c.ApiToken)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			log.Println(err)
			http.Error(w, fmt.Sprintf("Error fetching ticket data: %w", err), http.StatusInternalServerError)
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
			http.Error(w, fmt.Sprintf("Error parsing ticket data: %w", err), http.StatusInternalServerError)
			return
		}

		t, err := template.ParseFiles("templates/ticket.html")
		if err != nil {
			log.Println(err)
			http.Error(w, fmt.Sprintf("Internal server error: %w", err), http.StatusInternalServerError)
			return
		}

		t.Execute(w, ticket)

	}
}

func handleLogin(c *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var audParam oauth2.AuthCodeOption = oauth2.SetAuthURLParam("audience", c.Auth.Audience)
		http.Redirect(w, r, c.Auth.AuthCodeURL("state", audParam), http.StatusTemporaryRedirect)
	}
}

func handleCallback(c *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		oauth2Token, err := c.Auth.Exchange(ctx, r.URL.Query().Get("code"))
		if err != nil {
			log.Println(err)
			http.Error(w, fmt.Sprintf("Failed to exchange token: %w", err), http.StatusInternalServerError)
			return
		}

		_, err = c.Auth.VerifyIDToken(ctx, oauth2Token)
		if err != nil {
			log.Println(err)
			http.Error(w, fmt.Sprintf("Failed to verify ID token: %w", err), http.StatusInternalServerError)
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
