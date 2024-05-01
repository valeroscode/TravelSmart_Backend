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
	ID        int       `json:"id"`
	Name      string    `json:"name"`
	Email     string    `json:"email"`
	Password  string    `json:"password"`
	Favorites *[]string `json:"favorites"`
	Trips     Trips     `json:"trips"`
}

type tripDetails struct {
	City  string              `json:"city"`
	Dates []string            `json:"dates"`
	Plans map[string][]string `json:"plans"`
	Year  int                 `json:"year"`
}

type Trips struct {
	Trips map[string]tripDetails `json:"trips"`
}

type Days map[string][]string

type Credentials struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}
type UserService struct {
	db         *sql.DB
	emailIndex int
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

func (us *UserService) getUser(w http.ResponseWriter, r *http.Request, db *sql.DB) {

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
	var favorites *[]string
	var trips json.RawMessage
	var id int
	quErr := db.QueryRow("SELECT password, name, favorites, trips, id FROM users WHERE email = $1", email).Scan(&storedHash, &name, &favorites, &trips, &id)
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

	_, indexErr := us.db.Exec("CREATE INDEX IF NOT EXISTS idx_email ON users (email)")
	if indexErr != nil {
		return
	}

	us.emailIndex = id

	fmt.Println(us.emailIndex)

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

func (us *UserService) updateFavorites(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	fmt.Println(us.emailIndex)
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

	switch requestBody.Operation {
	case "append":
		var currentArray sql.NullString
		err = db.QueryRow("SELECT favorites FROM users WHERE id = $1", us.emailIndex).Scan(&currentArray)
		if currentArray.Valid {
			_, err = db.Exec("UPDATE users SET favorites = ARRAY_APPEND(favorites, $1) WHERE id = $2", us.emailIndex, requestBody.Email)
			if err != nil {
				log.Println(err)
			}
		} else {
			array := []string{requestBody.Item}
			_, err = db.Exec("UPDATE users SET favorites = $1 WHERE id = $2", pq.Array(array), us.emailIndex)
			if err != nil {
				log.Println(err)
			}

		}
		if err != nil {
			fmt.Println("Error fetching array from database:", err)
			return
		}

	case "remove":
		_, err = db.Exec("UPDATE users SET favorites = CASE WHEN favorites IS NULL OR favorites = '{}' THEN '{}' ELSE ARRAY_REMOVE(favorites, $1) END WHERE id = $2", requestBody.Item, us.emailIndex)
		if err != nil {
			log.Println(err)
		}
	default:
		http.Error(w, "Invalid operation", http.StatusBadRequest)
		return
	}
}

func (us *UserService) updateName(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	fmt.Println(us.emailIndex)
	var requestBody struct {
		Email string `json:"email"`
		Name  string `json:"name"`
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

	_, err = db.Exec("UPDATE users SET name = $1 WHERE id = $2", requestBody.Name, us.emailIndex)
	if err != nil {
		log.Println(err)
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

func (us *UserService) deleteUser(w http.ResponseWriter, r *http.Request, db *sql.DB) {
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

	quErr := db.QueryRow("SELECT password FROM users WHERE id = $1", us.emailIndex).Scan(&storedHash)
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

	db.Exec("DELETE FROM users WHERE id = $1", us.emailIndex)

	json.NewEncoder(w).Encode(struct {
		Status string `json:"status"`
		User   string `json:"user"`
	}{
		Status: "deleted",
		User:   requestBody.Email,
	})
}

func (us *UserService) createTrip(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	var requestBody struct {
		Email string              `json:"email"`
		Name  string              `json:"name"`
		City  string              `json:"city"`
		Dates []string            `json:"dates"`
		Plans map[string][]string `json:"plans"`
		Year  int                 `json:"year"`
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

	trip := tripDetails{
		City:  requestBody.City,
		Dates: requestBody.Dates,
		Plans: requestBody.Plans,
		Year:  requestBody.Year,
	}

	var trips Trips
	var tempTrips Trips
	trips.Trips = make(map[string]tripDetails)

	query := "SELECT trips FROM users WHERE id = $1"

	row := db.QueryRow(query, us.emailIndex)
	var tripsJSON []byte
	switch err := row.Scan(&tripsJSON); {
	case err != nil:
		return
	case tripsJSON != nil:
		err = json.Unmarshal(tripsJSON, &tempTrips)
		if err != nil {
			return
		}

		trips.Trips[requestBody.Name] = trip

		for k, v := range tempTrips.Trips {
			trips.Trips[k] = v
		}
	}

	tripsJSON, err = json.Marshal(trips)
	if err != nil {
		return
	}

	//Update the user row with the new trip data
	query = "UPDATE users SET trips = $1 WHERE id = $2"
	_, err = db.Exec(query, tripsJSON, us.emailIndex)
	if err != nil {
		return
	}
}

func (us *UserService) updateTripName(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	var requestBody struct {
		Email   string              `json:"email"`
		Newname string              `json:"newname"`
		Trip    string              `json:"tripname"`
		City    string              `json:"city"`
		Year    int                 `json:"year"`
		Dates   []string            `json:"dates"`
		Plans   map[string][]string `json:"plans"`
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

	var trips Trips
	var tempTrips Trips
	trips.Trips = make(map[string]tripDetails)

	query := "SELECT trips FROM users WHERE id = $1"
	row := db.QueryRow(query, us.emailIndex)

	var tripsJSON []byte
	switch err := row.Scan(&tripsJSON); {
	case err != nil:
		return
	case tripsJSON != nil:
		err = json.Unmarshal(tripsJSON, &tempTrips)
		if err != nil {
			return
		}
		tripsCopy := tripDetails{}
		tripsCopy.City = requestBody.City
		tripsCopy.Dates = requestBody.Dates
		tripsCopy.Plans = requestBody.Plans
		tripsCopy.Year = requestBody.Year

		trips.Trips[requestBody.Newname] = tripsCopy

		for k, v := range tempTrips.Trips {
			trips.Trips[k] = v
		}

		delete(trips.Trips, requestBody.Trip)

	}

	tripsJSON, err = json.Marshal(trips)
	if err != nil {
		return
	}

	query = "UPDATE users SET trips = $1 WHERE id = $2"
	_, err = db.Exec(query, tripsJSON, us.emailIndex)
	if err != nil {
		return
	}
}

func (us *UserService) updateTrip(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	var requestBody struct {
		Email string              `json:"email"`
		Trip  string              `json:"tripname"`
		City  string              `json:"city"`
		Year  int                 `json:"year"`
		Dates []string            `json:"dates"`
		Plans map[string][]string `json:"plans"`
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

	var trips Trips
	var tempTrips Trips
	trips.Trips = make(map[string]tripDetails)

	query := "SELECT trips FROM users WHERE id = $1"
	row := db.QueryRow(query, us.emailIndex)

	var tripsJSON []byte
	switch err := row.Scan(&tripsJSON); {
	case err != nil:
		return
	case tripsJSON != nil:
		err = json.Unmarshal(tripsJSON, &tempTrips)
		if err != nil {
			return
		}
		tripsCopy := tripDetails{}
		tripsCopy.City = requestBody.City
		tripsCopy.Dates = requestBody.Dates
		tripsCopy.Plans = requestBody.Plans
		tripsCopy.Year = requestBody.Year

		for k, v := range tempTrips.Trips {
			trips.Trips[k] = v
		}

		trips.Trips[requestBody.Trip] = tripsCopy

	}

	tripsJSON, err = json.Marshal(trips)
	if err != nil {
		return
	}

	query = "UPDATE users SET trips = $1 WHERE id = $2"
	_, err = db.Exec(query, tripsJSON, us.emailIndex)
	if err != nil {
		return
	}

}

func createUserHandler(db *sql.DB) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		createUser(w, r, db)
	}
}

func getUserHandler(db *sql.DB) func(w http.ResponseWriter, r *http.Request) {
	us := &UserService{db: db}
	return func(w http.ResponseWriter, r *http.Request) {
		r.Header.Set("Content-Type", "application/json")
		us.getUser(w, r, db)
	}
}

func deleteUserHandler(db *sql.DB) func(w http.ResponseWriter, r *http.Request) {
	us := &UserService{db: db}
	return func(w http.ResponseWriter, r *http.Request) {
		r.Header.Set("Content-Type", "application/json")
		us.deleteUser(w, r, db)
	}
}

func updateFavoritesHandler(db *sql.DB) func(w http.ResponseWriter, r *http.Request) {
	us := &UserService{db: db}
	return func(w http.ResponseWriter, r *http.Request) {
		r.Header.Set("Content-Type", "application/json")
		us.updateFavorites(w, r, db)
	}
}

func updateNameHandler(db *sql.DB) func(w http.ResponseWriter, r *http.Request) {
	us := &UserService{db: db}
	return func(w http.ResponseWriter, r *http.Request) {
		r.Header.Set("Content-Type", "application/json")
		us.updateName(w, r, db)
	}
}

func createTripHandler(db *sql.DB) func(w http.ResponseWriter, r *http.Request) {
	us := &UserService{db: db}
	return func(w http.ResponseWriter, r *http.Request) {
		r.Header.Set("Content-Type", "application/json")
		us.createTrip(w, r, db)
	}
}

func updateTripNameHandler(db *sql.DB) func(w http.ResponseWriter, r *http.Request) {
	us := &UserService{db: db}
	return func(w http.ResponseWriter, r *http.Request) {
		r.Header.Set("Content-Type", "application/json")
		us.updateTripName(w, r, db)
	}
}

func updateTripHandler(db *sql.DB) func(w http.ResponseWriter, r *http.Request) {
	us := &UserService{db: db}
	return func(w http.ResponseWriter, r *http.Request) {
		r.Header.Set("Content-Type", "application/json")
		us.updateTrip(w, r, db)
	}
}
