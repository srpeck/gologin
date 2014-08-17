package main

import (
	"fmt"
	"github.com/gorilla/securecookie"
	"github.com/zenazn/goji/graceful"
	"github.com/zenazn/goji/web"
	"github.com/zenazn/goji/web/middleware"
	"log"
	"net/http"
)

var s = securecookie.New(securecookie.GenerateRandomKey(64), securecookie.GenerateRandomKey(32)) // Should generate static key so server restart doesn't invalidate cookies

func SetCookieHandler(w http.ResponseWriter, r *http.Request, username string) {
	value := map[string]string{"username": username}
	if encoded, err := s.Encode("user", value); err == nil {
		cookie := &http.Cookie{
			Name:  "user",
			Value: encoded,
			Path:  "/",
		}
		http.SetCookie(w, cookie)
	}
}

func ReadCookieHandler(w http.ResponseWriter, r *http.Request) (username string) {
	if cookie, err := r.Cookie("user"); err == nil {
		value := make(map[string]string)
		if err = s.Decode("user", cookie.Value, &value); err == nil {
			username = value["username"]
		}
	}
	return username
}

func ClearCookie(w http.ResponseWriter, r *http.Request) {
	cookie := &http.Cookie{
		Name:   "user",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	}
	http.SetCookie(w, cookie)
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")
	redirect := "/"
	if username != "" && password != "" {
		user, err := FindUser(username)
		if err != nil {
			fmt.Printf("Failed login as username: %s\n", username)
		} else {
			err = ComparePassword(user.Password, password)
			if err != nil {
				fmt.Printf("Failed login as username: %s\n", username)
			} else {
				SetCookieHandler(w, r, username)
				redirect = "/internal"
				fmt.Printf("Successful login as username: %s\n", user.Username)
			}
		}
	}
	http.Redirect(w, r, redirect, 302)
}

func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	ClearCookie(w, r)
	http.Redirect(w, r, "/", 302)
}

const indexPage = `
<h1>Login</h1>
<form method="post" action="/login">
    <label for="username">Username</label>
    <input type="text" id="username" name="username"><br>
    <label for="password">Password</label>
    <input type="password" id="password" name="password"><br>
    <button type="submit">Login</button>
</form>
<br><h1>Create Account</h1>
<form method="post" action="/signup">
    <label for="username">Username</label>
    <input type="text" id="username" name="username"><br>
    <label for="email">Email Address</label>
    <input type="text" id="email" name="email"><br>
    <label for="password">Password</label>
    <input type="password" id="password" name="password"><br>
    <button type="submit">Login</button>
</form>
`

func IndexPageHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, indexPage)
}

func SignupHandler(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	email := r.FormValue("email")
	password := r.FormValue("password")
	redirect := "/"
	if username != "" && email != "" && password != "" {
		id, err := InsertUser(User{Username: username, Password: password, Email: email})
		if err != nil {
			fmt.Printf("Failed create and login as username: %s\n", username)
		} else {
			SetCookieHandler(w, r, username)
			redirect = "/internal"
			fmt.Printf("Successful create and login as username: %s, id: %d\n", username, id)
		}
	}
	http.Redirect(w, r, redirect, 302)
}

const internalPage = `
<h1>Internal</h1>
User: %s
<form method="post" action="/logout">
    <button type="submit">Logout</button>
</form>
<br><h1>Update Information</h1>
<form method="post" action="/update">
    <label for="email">Email Address</label>
    <input type="text" id="email" name="email" value="%s"><br>
    <label for="password">Password</label>
    <input type="password" id="password" name="password"><br>
    <button type="submit">Update</button>
</form>
`

func InternalPageHandler(w http.ResponseWriter, r *http.Request) {
	username := ReadCookieHandler(w, r)
	if username != "" {
		user, err := FindUser(username)
		if err != nil {
			http.Redirect(w, r, "/", 302)
		}
		fmt.Fprintf(w, internalPage, username, user.Email)
	} else {
		http.Redirect(w, r, "/", 302)
	}
}

func UpdateHandler(w http.ResponseWriter, r *http.Request) {
	username := ReadCookieHandler(w, r)
	email := r.FormValue("email")
	password := r.FormValue("password")
	redirect := "/"
	if username != "" {
		redirect = "/internal"
		if email != "" && password != "" {
			_ = UpdateUser(User{Username: username, Password: password, Email: email})
		}
	}
	http.Redirect(w, r, redirect, 302)
}

func main() {
	r := web.New()
	r.Use(middleware.RequestID)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.AutomaticOptions)

	r.Get("/", IndexPageHandler)
	r.Get("/internal", InternalPageHandler)
	r.Post("/signup", SignupHandler)
	r.Post("/update", UpdateHandler)
	r.Post("/login", LoginHandler)
	r.Post("/logout", LogoutHandler)

	graceful.HandleSignals()
	log.Println("Starting Goji https server on :8080")
	err := graceful.ListenAndServeTLS(":8080", "ssl_credentials/certificate.pem", "ssl_credentials/privatekey.pem", r)
	if err != nil {
		log.Fatal(err)
	}
	graceful.Wait()
}
