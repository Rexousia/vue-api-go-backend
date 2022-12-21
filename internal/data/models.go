package data

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base32"
	"errors"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const dbTimeout = time.Second * 3

var db *sql.DB

// New creates and returns a new Models struct with fields initialized to their zero values.
func New(dbPool *sql.DB) Models {
	// Set the global db variable to the provided database connection pool.
	db = dbPool

	// Return a new Models struct with fields initialized to their zero values.
	return Models{
		User:  User{},
		Token: Token{},
	}
}

type Models struct {
	User  User
	Token Token
}
type User struct {
	ID        int       `json:"id"`
	Email     string    `json:email`
	FirstName string    `json:"first_name, omitempty"`
	LastName  string    `json:"last_name, omitempty"`
	Password  string    `json:"password"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Token     Token     `json:"token"`
}

// GetAll retrieves all rows from the "users" table and returns them as a slice of User structs.
func (u *User) GetAll() ([]*User, error) {
	// Create a context with a timeout for the database operation.
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()

	// Select all rows from the "users" table, sorted by last name.
	query := `select id, email, first_name, last_name, password, created_at, updated_at from users order by last_name`
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []*User

	// For each row, scan the values into a new User struct and append it to the users slice.
	for rows.Next() {
		var user User
		err := rows.Scan(
			&user.ID,
			&user.Email,
			&user.FirstName,
			&user.LastName,
			&user.Password,
			&user.CreatedAt,
			&user.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		users = append(users, &user)
	}

	// Return the slice of User structs.
	return users, nil
}

// Get by email
// GetByEmail retrieves a single User struct from the database by email.
func (u *User) GetByEmail(email string) (*User, error) {
	// Create a context with a timeout for the database operation.
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()

	// Select the row in the "users" table with the given email.
	query := `select id, email, first_name, last_name, password, created_at, updated_at from users where email = $1`

	var user User
	row := db.QueryRowContext(ctx, query, email)

	// Scan the selected row into the User struct.
	err := row.Scan(
		&user.ID,
		&user.Email,
		&user.FirstName,
		&user.LastName,
		&user.Password,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	// Return the User struct.
	return &user, nil
}

// GetOne retrieves a single User struct from the database by ID.
func (u *User) GetOne(id int) (*User, error) {
	// Create a context with a timeout for the database operation.
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()

	// Select the row in the "users" table with the given ID.
	query := `select id, email, first_name, last_name, password, created_at, updated_at from users where id = $1`

	var user User
	row := db.QueryRowContext(ctx, query, id)

	// Scan the selected row into the User struct.
	err := row.Scan(
		&user.ID,
		&user.Email,
		&user.FirstName,
		&user.LastName,
		&user.Password,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	// Return the User struct.
	return &user, nil
}

func (u *User) Update() error {
	// Create a context with a timeout for the database operation.
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()

	// Update the fields of the row in the "users" table with the fields of the User struct.
	stmt := `update users set
		email = $1
		first_name = $2
		last_name = $3
		updated_at = $4
		where id = $5
	`
	// Execute the query without returning rows.
	_, err := db.ExecContext(ctx, stmt,
		u.Email,
		u.FirstName,
		u.LastName,
		time.Now(),
		u.ID,
	)
	if err != nil {
		return err
	}

	return nil
}

// Deleting a User from the User table
func (u *User) Delete() error {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()

	stmt := `delete from users where id = $1`

	//Executing query without returning rows
	_, err := db.ExecContext(ctx, stmt, u.ID)

	if err != nil {
		return err
	}

	return nil
}

// Inserting a user into the DB
// Insert inserts the given User struct into the database and returns the ID of the inserted row.
func (u *User) Insert(user User) (int, error) {
	// Create a context with a timeout for the database operation.
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()

	// Hash the password field of the given User struct using bcrypt.
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), 12)
	if err != nil {
		return 0, err
	}

	// Insert the User struct into the "users" table and return the ID of the inserted row.
	var newID int
	stmt := `insert into users (email, first_name, last_name, password, created_at, updated_at)
		values ($1, $2, $3, $4, $5, $6) returning id
	`
	err = db.QueryRowContext(ctx, stmt,
		user.Email,
		user.FirstName,
		user.LastName,
		hashedPassword,
		time.Now(),
		time.Now(),
	).Scan(&newID)

	if err != nil {
		// Return 0 and the error if there was an error executing the query.
		return 0, err
	}

	// Return the ID of the inserted row.
	return newID, nil
}

// ResetPassword updates the password field of the User struct in the database with the given password.
func (u *User) ResetPassword(password string) error {
	// Create a context with a timeout for the database operation.
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()

	// Hash the given password using bcrypt.
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	if err != nil {
		return err
	}

	// Update the "password" field of the row in the "users" table with the hashed password.
	stmt := `update users set password = $1 where id = $2`
	_, err = db.ExecContext(ctx, stmt, hashedPassword, u.ID)
	if err != nil {
		return err
	}

	return nil
}

// Checking to see if password entered mactches.
func (u *User) PasswordMatches(plainText string) (bool, error) {
	err := bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(plainText))

	if err != nil {
		switch {
		case errors.Is(err, bcrypt.ErrMismatchedHashAndPassword):
			//invalid password
			return false, nil
		default:
			return false, err
		}

	}
	return true, nil
}

// Token is the data structure for any token in the database. Note that
// we do not send the TokenHash (a slice of byte) in any exported JSON
type Token struct {
	ID     int    `json:"id"`
	UserID int    `json:"user_id"`
	Email  string `json:"email"`
	Token  string `json:"token"`
	//not going to send it
	TokenHash []byte    `json:"-"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Expiry    time.Time `json:"expiry"`
}

// GetByToken retrieves the Token struct from the database that matches the given token string.
func (t *Token) GetByToken(plainText string) (*Token, error) {
	// Create a context with a timeout for the database operation.
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()

	// Query the "tokens" table for the row with a "token" field matching the given token string.
	query := `select id, user_id, email, token, token_hash, created_at, updated_at, expiry
			from tokens where token = $1
	`

	var token Token

	// Execute the query and scan the result into the Token struct.
	row := db.QueryRowContext(ctx, query, plainText)
	err := row.Scan(
		&token.ID,
		&token.UserID,
		&token.Email,
		&token.Token,
		&token.TokenHash,
		&token.CreatedAt,
		&token.UpdatedAt,
		&token.Expiry,
	)
	if err != nil {
		// Return nil and the error if there was an error executing the query.
		return nil, err
	}

	// Return a pointer to the Token struct.
	return &token, nil
}

// GetUserForToken retrieves the User struct associated with the given Token struct from the database.
func (t *Token) GetUserForToken(token Token) (*User, error) {
	// Create a context with a timeout for the database operation.
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()

	// Query the "users" table for the row with the ID matching the UserID field of the Token struct.
	query := `select id, email, first_name, last_name, password, created_at, updated_at from users where id = $1`

	var user User

	// Execute the query and scan the result into the User struct.
	row := db.QueryRowContext(ctx, query, token.UserID)
	err := row.Scan(
		&user.ID,
		&user.Email,
		&user.FirstName,
		&user.LastName,
		&user.Password,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err != nil {
		// Return nil and the error if there was an error executing the query.
		return nil, err
	}

	// Return a pointer to the User struct.
	return &user, nil
}

// GenerateToken generates a new token for the given user ID and time-to-live duration.
func (t *Token) GenerateToken(userID int, ttl time.Duration) (*Token, error) {
	// Create a new Token struct with the given user ID and Expiry set to the current time plus the ttl duration.
	token := &Token{
		UserID: userID,
		Expiry: time.Now().Add(ttl),
	}

	// Create a byte slice of random characters using the "letterBytes" string and the math/rand package.
	const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	randomBytes := make([]byte, 16)
	for i := range randomBytes {
		randomBytes[i] = letterBytes[rand.Int63()%int64(len(letterBytes))]
	}

	// Use the crypto/rand package to read more random bytes into the randomBytes slice.
	_, err := rand.Read(randomBytes)
	if err != nil {
		// Return nil and the error if there was an error reading random bytes.
		return nil, err
	}

	// Encode the randomBytes slice into a base32-encoded string and set it as the Token field of the Token struct.
	token.Token = base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(randomBytes)

	// Calculate the SHA-256 hash of the Token field and set it as the TokenHash field of the Token struct.
	hash := sha256.Sum256([]byte(token.Token))
	token.TokenHash = hash[:]

	// Return the Token struct.
	return token, nil
}

// AuthenticateToken authenticates the token passed in the "Authorization" header of the given HTTP request.
func (t *Token) AuthenticateToken(r *http.Request) (*User, error) {
	// Get the "Authorization" header from the request.
	authortizationHeader := r.Header.Get("Authorization")

	if authortizationHeader == "" {
		// Return nil and an error if the header is not present.
		return nil, errors.New("no authorization header received")
	}

	// Split the header on the space character to get the "Bearer" token type and the actual token.
	headerParts := strings.Split(authortizationHeader, " ")
	if len(headerParts) != 2 || headerParts[0] != "Bearer" {
		// Return nil and an error if the header is not in the expected format.
		return nil, errors.New("no valid authorization header received")
	}

	// Get the token from the header.
	token := headerParts[1]

	if len(token) != 26 {
		// Return nil and an error if the token is not the expected length.
		return nil, errors.New("token wrong size")
	}

	// Get the Token struct from the database that matches the given token.
	tkn, err := t.GetByToken(token)
	if err != nil {
		// Return nil and an error if there is no matching token in the database.
		return nil, errors.New("no matching token found")
	}

	if tkn.Expiry.Before(time.Now()) {
		// Return nil and an error if the token has expired.
		return nil, errors.New("expired token")
	}

	// Get the User struct that is associated with the token.
	user, err := t.GetUserForToken(*tkn)
	if err != nil {
		// Return nil and an error if there is no matching user in the database.
		return nil, errors.New("no matching user found")
	}

	// Return the User struct.
	return user, nil
}

// Insert inserts the given Token and User structs into the database.
func (t *Token) Insert(token Token, u User) error {
	// Create a context with a timeout for the database operations.
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()

	// Delete any existing tokens in the database for the user.
	stmt := `delete from tokens where user_id = $1`
	_, err := db.ExecContext(ctx, stmt, token.UserID)
	if err != nil {
		return err
	}

	// Set the Email field of the Token struct to the Email field of the User struct.
	token.Email = u.Email

	// Insert the Token and User structs into the "tokens" table.
	stmt = `insert into tokens (user_id, email, token, token_hash, created_at, updated_at, expiry)
		values ($1, $2, $3, $4, $5, $6 ,$7)`
	_, err = db.ExecContext(ctx, stmt,
		token.UserID,
		token.Email,
		token.Token,
		token.TokenHash,
		time.Now(),
		time.Now(),
		token.Expiry,
	)
	if err != nil {
		return err
	}

	return nil
}

// DeleteByToken delete a token, by plain text token.
func (t *Token) DeleteByToken(plainText string) error {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()

	stmt := `delete from tokens where token = $1`

	_, err := db.ExecContext(ctx, stmt, plainText)
	if err != nil {
		return err
	}

	return nil
}

// ValidToken checks if the given token string is a valid, unexpired token in the database.
func (t *Token) ValidToken(plainText string) (bool, error) {
	// Get the Token struct from the database that matches the given token string.
	token, err := t.GetByToken(plainText)
	if err != nil {
		// Return false and an error if there is no matching token in the database.
		return false, errors.New("No matching token found")
	}

	// Get the User struct associated with the Token struct.
	_, err = t.GetUserForToken(*token)
	if err != nil {
		// Return false and an error if there is no matching user in the database.
		return false, errors.New("No matching user found")
	}

	if token.Expiry.Before(time.Now()) {
		// Return false and an error if the token has expired.
		return false, errors.New("expired token")
	}

	// Return true if the token is valid and unexpired.
	return true, nil
}
