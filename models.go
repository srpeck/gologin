package main

import (
	"code.google.com/p/go.crypto/bcrypt"
	"database/sql"
	"errors"
	_ "github.com/lib/pq"
	"regexp"
)

type User struct {
	Id       int
	Username string
	Password string
	Email    string
}

func ComparePassword(password string, possible string) error {
	return bcrypt.CompareHashAndPassword([]byte(password), []byte(possible))
}

func FindUser(username string) (u User, err error) {
	var user User
	db, err := sql.Open("postgres", "postgres://chess:chess@localhost:5432/chess?sslmode=disable")
	if err == nil {
		err = db.QueryRow("SELECT id, username, password, email FROM \"Users\" WHERE username=$1;", username).Scan(&user.Id, &user.Username, &user.Password, &user.Email)
	}
	return user, err
}

func InsertUser(user User) (int, error) {
	db, err := sql.Open("postgres", "postgres://chess:chess@localhost:5432/chess?sslmode=disable")
	if err == nil {
		if validUsername(user.Username) && validPassword(user.Password) && validEmail(user.Email) {
			hash, _ := bcrypt.GenerateFromPassword([]byte(user.Password), 10)
			err = db.QueryRow("INSERT INTO \"Users\" (username, password, email) VALUES ($1, $2, $3) RETURNING id", user.Username, hash, user.Email).Scan(&user.Id)
		} else {
			err = errors.New("Invalid input")
		}
	}
	return user.Id, err
}

func UpdateUser(user User) error {
	db, err := sql.Open("postgres", "postgres://chess:chess@localhost:5432/chess?sslmode=disable")
	if err == nil {
		if validUsername(user.Username) && validPassword(user.Password) && validEmail(user.Email) {
			hash, _ := bcrypt.GenerateFromPassword([]byte(user.Password), 10)
			err = db.QueryRow("UPDATE \"Users\" SET password=$1, email=$2 WHERE username=$3", hash, user.Email, user.Username).Scan(&user.Id)
		} else {
			err = errors.New("Invalid input")
		}
	}
	return err
}

func validUsername(username string) bool {
	match, _ := regexp.MatchString("\\w{3,50}", username)
	return match
}
func validPassword(password string) bool {
	match, _ := regexp.MatchString(".{6,50}", password)
	return match
}
func validEmail(email string) bool {
	match, _ := regexp.MatchString("^(([^<>()[\\]\\.,;:\\s@\"]+(\\.[^<>()[\\]\\.,;:\\s@\"]+)*)|(\".+\"))@((\\[[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\])|(([a-zA-Z\\-0-9]+\\.)+[a-zA-Z]{2,}))$", email)
	return match
}
