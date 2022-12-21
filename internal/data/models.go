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

func New(dbPool *sql.DB) Models {
	db = dbPool

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

// Getting all entries
func (u *User) GetAll() ([]*User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()

	query := `select id, email, first_name, last_name, password, created_at, updated_at from users order by last_name`
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []*User

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

	return users, nil
}

// Get by email
func (u *User) GetByEmail(email string) (*User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()

	query := `select id, email, first_name, last_name, password, created_at, updated_at from users where email = $1`

	var user User
	row := db.QueryRowContext(ctx, query, email)

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

	return &user, nil
}

// Getting user by ID
func (u *User) GetOne(id int) (*User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()

	query := `select id, email, first_name, last_name, password, created_at, updated_at from users where id = $1`

	var user User
	row := db.QueryRowContext(ctx, query, id)

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

	return &user, nil
}

// Updating an entry inside of the User Table
func (u *User) Update() error {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()

	stmt := `update users set
		email = $1
		first_name = $2
		last_name = $3
		updated_at = $4
		where id = $5
	`
	//Executing query without returning rows
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
func (u *User) Insert(user User) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), 12)
	if err != nil {
		return 0, err
	}
	var newID int
	stmt := `insert into users (email, first_name, last_name, password, created_at, updated_at)
		values ($1, $2, $3, $4, $5, $6) returning id
	`
	// QueryRowContext executes a query that is expected to return at most one row.
	// QueryRowContext always returns a non-nil value. Errors are deferred until Row's Scan method is called.
	// If the query selects no rows, the *Row's Scan will return ErrNoRows.
	// Otherwise, the *Row's Scan scans the first selected row and discards the rest.
	err = db.QueryRowContext(ctx, stmt,
		user.Email,
		user.FirstName,
		user.LastName,
		hashedPassword,
		time.Now(),
		time.Now(),
	).Scan(&newID)

	if err != nil {
		return 0, err
	}

	return newID, nil
}

// Resets the password for a user in a database.
// It first sets up a context with a timeout using the context package.
// This context is used to ensure that database operations are cancelled if they take too long.
// The function then hashes the new password using the bcrypt package, with a cost of 12.
// The hashed password is then used to update the password for the user in the users table,
// using the db.ExecContext function and a SQL statement.
// The function returns an error if any of the steps fail.
// If all steps are successful, the function returns nil.
func (u *User) ResetPassword(password string) error {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	if err != nil {
		return err
	}

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
	UserID int    `json:"id"`
	Email  string `json:"email"`
	Token  string `json:"token"`
	//not going to send it
	TokenHash []byte    `json:"-"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Expiry    time.Time `json:"expiry"`
}

// Getting by token
func (t *Token) GetByToken(plainText string) (*Token, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()

	query := `select id, user_id, email, token, token_hash, created_at, updated_at, expiry
			from tokens where token = $1
	`

	var token Token

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
		return nil, err
	}
	return &token, nil
}

// GetUserForToken takes a token parameter, and uses the UserID field from that parameter
// to look a user up by id. It returns a pointer to the user model.
// function that retrieves a user from a database based on a given token.
// It first sets up a context with a timeout using the context package.
// This context is used to ensure that database operations are cancelled if they take too long.
// The function then creates a SQL query that selects the user's information from the users table based on the user's
// ID, which is stored in the token. It uses the db.QueryRowContext function to execute the query and retrieve the row
// of data for the user.
// The function scans the retrieved row and stores the data in a User struct.
// It then returns a pointer to the User struct and any error that may have occurred.
// If the query and scanning are successful, the function returns a pointer to the User struct and nil for the error.
// If there is an error, the function returns nil for the user and the error.
func (t *Token) GetUserForToken(token Token) (*User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()

	query := `select id, email, first_name, last_name, password, created_at, updated_at from users where id = $1`

	var user User

	row := db.QueryRowContext(ctx, query, token)

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

	return &user, nil
}

// This code defines a method named GenerateToken on a struct type called Token. The method has two parameters:
// userID of type int and ttl of type time.Duration.
// The method returns a pointer to a Token struct and an error.
// The method creates a new Token struct and assigns the value of userID to the UserID field of the struct
// and the value of time.Now().Add(ttl) to the Expiry field of the struct.
// It then generates a random slice of bytes called randomBytes using the rand package
// and converts it to a base32-encoded string, which is assigned to the Token field of the struct.
// It then calculates the SHA-256 hash of the token string and
// assigns the hash to the TokenHash field of the struct.
// Finally, the method returns the Token struct and nil as the error value.
func (t *Token) GenerateToken(userID int, ttl time.Duration) (*Token, error) {
	token := &Token{
		UserID: userID,
		Expiry: time.Now().Add(ttl),
	}
	const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	// creating token

	randomBytes := make([]byte, 16)
	for i := range randomBytes {
		randomBytes[i] = letterBytes[rand.Int63()%int64(len(letterBytes))]
	}
	_, err := rand.Read(randomBytes)
	if err != nil {
		return nil, err
	}

	token.Token = base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(randomBytes)

	//Getting has for the token
	hash := sha256.Sum256([]byte(token.Token))
	token.TokenHash = hash[:]

	return token, nil
}

// authenticating a token
// It retrieves the "Authorization" header from the request using r.Header.Get("Authorization").
// It checks if the authorization header is present.
// If it is not, the function returns nil and an error with the message "no authorization header received".

// It splits the authorization header into two parts using the strings.Split function, separating the parts using a
// space.

// It checks if the split resulted in two parts and if the first part is "Bearer".
// If either of these conditions is not met, the function returns nil and an error with the message
// "no valid authorization header received".

// It retrieves the second part of the split, which is the token,
// and checks if it is the correct size (26 characters).
// If it is not, the function returns nil and an error with the message "token wrong size".

// It calls the GetByToken function, passing in the token, to retrieve the token information from the database.
// If this returns an error, the function returns nil and an error with the message "no matching token found".

// It checks if the token has expired by comparing its expiry time to the current time.
// If the token has expired, the function returns nil and an error with the message "expired token".

// It calls the GetUserForToken function, passing in the retrieved token information,
// to retrieve the user associated with the token from the database. If this returns an error,
// the function returns nil and an error with the message "no matching user found".

// If all checks pass, the function returns a pointer to the user and nil for the error.
func (t *Token) AuthenticateToken(r *http.Request) (*User, error) {
	authortizationHeader := r.Header.Get("Authorization")

	if authortizationHeader == "" {
		return nil, errors.New("no authorization header received")
	}

	headerParts := strings.Split(authortizationHeader, " ")
	if len(headerParts) != 2 || headerParts[0] != "Bearer" {
		return nil, errors.New("no valid authorization header received")
	}

	token := headerParts[1]

	if len(token) != 26 {
		return nil, errors.New("token wrong size")
	}

	tkn, err := t.GetByToken(token)
	if err != nil {
		return nil, errors.New("no matching token found")
	}

	if tkn.Expiry.Before(time.Now()) {
		return nil, errors.New("expired token")
	}

	user, err := t.GetUserForToken(*tkn)
	if err != nil {
		return nil, errors.New("no matching user found")
	}

	return user, nil
}

// Function that inserts a new token into a database. It performs the following steps:

// It sets up a context with a timeout using the context package.
// This context is used to ensure that database operations are cancelled if they take too long.

// It executes a SQL statement to delete any existing tokens for the user associated with the new token,
// using the db.ExecContext function. If this operation fails, the function returns the error.

// It sets the email of the new token to the email of the user.

// It executes a SQL statement to insert the new token into the tokens table, using the db.ExecContext function.
// The function passes the values for each column as arguments to the statement.
// If this operation fails, the function returns the error.

// If both insertions are successful, the function returns nil.
func (t *Token) Insert(token Token, u User) error {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()

	//delete any existing tokens
	stmt := `delete from tokens where user_id = $1`
	_, err := db.ExecContext(ctx, stmt, token.UserID)
	if err != nil {
		return err
	}

	token.Email = u.Email

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

func (t *Token) ValidToken(plainText string) (bool, error) {
	token, err := t.GetByToken(plainText)
	if err != nil {
		return false, errors.New("No matching token found")
	}
	_, err = t.GetUserForToken(*token)
	if err != nil {
		return false, errors.New("No matching user found")
	}
	if token.Expiry.Before(time.Now()) {
		return false, errors.New("expired token")
	}

	return true, nil
}
