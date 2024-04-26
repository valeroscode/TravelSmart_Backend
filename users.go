package main

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID        int     `json:"id"`
	Name      string  `json:"name"`
	Email     string  `json:"email"`
	Password  string  `json:"password"`
	Favorites *string `json:"favorites"`
	Trips     Trips   `json:"trips"`
}

type Trip struct {
	City  string   `json:"city"`
	Dates []string `json:"dates"`
	Plans []Plan   `json:"plans"`
	Year  int      `json:"year"`
}

type Trips map[string]Trip

type Plan struct {
	Details string `json:"details"`
}

type Credentials struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func createUser(w http.ResponseWriter, r *http.Request, db *sql.DB) {

	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id SERIAL PRIMARY KEY,
			email VARCHAR(255) NOT NULL,
			password VARCHAR(255) NOT NULL
		);
	`)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var requestBody struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	jsonErr := json.NewDecoder(r.Body).Decode(&requestBody)
	if jsonErr != nil {
		http.Error(w, jsonErr.Error(), http.StatusBadRequest)
		return
	}

	requestBody.Email = strings.ToLower(requestBody.Email)

	// Check if the email already exists in the database
	err = db.QueryRow("SELECT email FROM users WHERE email = $1", requestBody.Email).Scan(&requestBody.Email)
	if err != nil {
		if err != sql.ErrNoRows {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	} else {
		http.Error(w, "Email already exists", http.StatusConflict)
		return
	}

	// Encrypt the password using bcrypt
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(requestBody.Password), 12)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Create a new user
	user := User{
		Email:    requestBody.Email,
		Password: string(hashedPassword),
	}

	var id int
	favoritesArray := pq.Array(user.Favorites)
	tripsJSON, err := json.Marshal(user.Trips)
	if err != nil {
		log.Println(err) // or your preferred logging method
		http.Error(w, "Error marshaling trips to JSON", http.StatusInternalServerError)
		return
	}
	sqlErr := db.QueryRow(`
	INSERT INTO users (name, email, password, favorites, trips) VALUES ($1, $2, $3, $4, $5) RETURNING id
    `, user.Name, user.Email, user.Password, favoritesArray, tripsJSON).Scan(&id)
	if sqlErr != nil {
		http.Error(w, sqlErr.Error(), http.StatusInternalServerError)
		return
	}

	user.ID = int(id)

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(user)
}

func getUser(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	var creds Credentials
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	email := creds.Email
	password := creds.Password

	var storedHash string
	var name string
	var favorites *string
	var trips json.RawMessage
	quErr := db.QueryRow("SELECT password, name, favorites, trips FROM users WHERE email = $1", email).Scan(&storedHash, &name, &favorites, &trips)
	if quErr == sql.ErrNoRows {
		http.Error(w, "Invalid email", http.StatusUnauthorized)
		return
	}
	if quErr != nil {
		log.Printf("Error retrieving user data: %v", quErr)
		http.Error(w, "Error retrieving user data", http.StatusInternalServerError)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(password)); err != nil {
		http.Error(w, "Invalid password", http.StatusUnauthorized)
		return
	}

	var tripData Trips
	err = json.Unmarshal(trips, &tripData)
	if err != nil {
		log.Printf("Error unmarshaling trips data: %v", err)
	}

	combinedUser := User{
		Email:     email,
		Name:      name,
		Trips:     tripData,
		Favorites: favorites, // Set Favorites to nil if it's null
	}

	// Encode and return the combined user data
	json.NewEncoder(w).Encode(combinedUser)
}

func updateUser(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	// Implement user update logic here
}

func deleteUser(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	// Implement user deletion logic here
}

func createUserHandler(db *sql.DB) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		createUser(w, r, db)
	}
}

func getUserHandler(db *sql.DB) func(w http.ResponseWriter, r *http.Request) {

	return func(w http.ResponseWriter, r *http.Request) {
		r.Header.Set("Content-Type", "application/json")
		getUser(w, r, db)
	}
}
