package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
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

	// Generate a token
	token, err := generateToken(combinedUser)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Return the token and user data
	json.NewEncoder(w).Encode(struct {
		Token string `json:"token"`
		User  User   `json:"user"`
	}{
		Token: token,
		User:  combinedUser,
	})
}

func generateToken(user User) (string, error) {
	jwtSecret := os.Getenv("JWT_SECRET")
	// Create a new token
	token := jwt.New(jwt.SigningMethodHS256)

	// Set the token claims
	claims := token.Claims.(jwt.MapClaims)
	claims["user_id"] = user.ID
	claims["email"] = user.Email
	claims["name"] = user.Name
	claims["exp"] = time.Now().Add(time.Hour * 24).Unix() // Token expires in 24 hours

	// Sign the token with a secret key
	tokenString, err := token.SignedString([]byte(jwtSecret))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func updateFavorites(w http.ResponseWriter, r *http.Request, db *sql.DB) {

	var requestBody struct {
		Email     string `json:"email"`
		Operation string `json:"operation"`
		Item      string `json:"item"`
	}

	jsonErr := json.NewDecoder(r.Body).Decode(&requestBody)
	if jsonErr != nil {
		http.Error(w, jsonErr.Error(), http.StatusBadRequest)
		return
	}

	requestBody.Email = strings.ToLower(requestBody.Email)
	// Extract the JWT token from the Authorization header
	authHeader := r.Header.Get("Authorization")
	jwtToken := strings.TrimPrefix(authHeader, "Bearer ")
	// Verify the JWT token
	valid, err := verifyJWT(jwtToken)
	if !valid {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	var array []string
	var arrayNull bool
	err = db.QueryRow("SELECT array, favorites IS NULL FROM users WHERE id = $1", requestBody.Email).Scan(&array, &arrayNull)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if arrayNull {
		array = []string{} // Initialize an empty slice if the column is null
	}
	err = db.QueryRow("SELECT favorites FROM users WHERE email = $1", requestBody.Email).Scan(&array)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	switch requestBody.Operation {
	case "append":
		array = append(array, requestBody.Item)
	case "remove":
		// Find the index of the item in the array
		index := -1
		for i, item := range array {
			if item == requestBody.Item {
				index = i
				break
			}
		}
		if index != -1 {
			array = append(array[:index], array[index+1:]...)
		}
	default:
		http.Error(w, "Invalid operation", http.StatusBadRequest)
		return
	}
}

func verifyJWT(token string) (bool, error) {
	jwtSecret := os.Getenv("JWT_SECRET")
	// Parse the JWT token
	parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		// Check the token's signature
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		// Return the secret key
		return []byte(jwtSecret), nil
	})
	if err != nil {
		return false, err
	}
	// Check if the token is valid
	if claims, ok := parsedToken.Claims.(jwt.MapClaims); ok && parsedToken.Valid {
		exp := claims["exp"]
		if exp != nil {
			if exp.(float64) < float64(time.Now().Unix()) {
				return false, nil
			}
		}
		return true, nil
	}
	return false, nil
}

func deleteUser(w http.ResponseWriter, r *http.Request, db *sql.DB) {
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

	var storedHash string

	quErr := db.QueryRow("SELECT password FROM users WHERE email = $1", requestBody.Email).Scan(&storedHash)
	if quErr == sql.ErrNoRows {
		http.Error(w, "Invalid email", http.StatusUnauthorized)
		return
	}
	if quErr != nil {
		log.Printf("Error retrieving user data: %v", quErr)
		http.Error(w, "Error retrieving user data", http.StatusInternalServerError)
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(requestBody.Password)); err != nil {
		http.Error(w, "Invalid password", http.StatusUnauthorized)
		return
	}

	db.Exec("DELETE FROM users WHERE email = $1", requestBody.Email)

	json.NewEncoder(w).Encode(struct {
		Status string `json:"status"`
		User   string `json:"user"`
	}{
		Status: "deleted",
		User:   requestBody.Email,
	})
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

func deleteUserHandler(db *sql.DB) func(w http.ResponseWriter, r *http.Request) {

	return func(w http.ResponseWriter, r *http.Request) {
		r.Header.Set("Content-Type", "application/json")
		deleteUser(w, r, db)
	}
}

func updateFavoritesHandler(db *sql.DB) func(w http.ResponseWriter, r *http.Request) {

	return func(w http.ResponseWriter, r *http.Request) {
		r.Header.Set("Content-Type", "application/json")
		updateFavorites(w, r, db)
	}
}
