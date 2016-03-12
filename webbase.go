/*
 *  Charon: A game authentication server
 *  Copyright (C) 2016  Alex Mayfield <alexmax2742@gmail.com>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Affero General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Affero General Public License for more details.
 *
 *  You should have received a copy of the GNU Affero General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package charon

import (
	"net/http"

	"golang.org/x/net/context"
)

// BaseTemplates contains template definitions for the base routes.
var BaseTemplates = TemplateDefs{
	"home":  TemplateNames{"layout", "header", "home"},
	"login": TemplateNames{"layout", "header", "login"},
}

// Home renders the homepage.
func (webApp *WebApp) Home(res http.ResponseWriter, req *http.Request) {
	webApp.RenderTemplate(&res, req, "home", nil)
}

// LoginData contains the context for the Login page.
type LoginData struct {
	Form   *LoginForm
	Errors FormErrors
}

// LoginForm contains the form data for the Login page.
type LoginForm struct {
	Login    string
	Password string
}

// Login renders the login page.
func (webApp *WebApp) Login(ctx context.Context, res http.ResponseWriter, req *http.Request) {
	data := NewLoginData(req)

	if req.Method != "GET" {
		// Validate the form
		data.Form = &LoginForm{
			Login:    req.PostFormValue("login"),
			Password: req.PostFormValue("password"),
		}
		var user *User
		user, data.Errors = data.Form.Validate(&webApp.database)
		if len(data.Errors) > 0 {
			webApp.RenderTemplate(&res, req, "login", data)
			return
		}

		// We have a user, but we don't actually want to store the salt or
		// verifier in the session, so blank them out.
		user.Salt = []byte("")
		user.Verifier = []byte("")

		// Store user in the session.
		session, err := webApp.sessionStore.Get(req, sessionName)
		if err != nil {
			http.Error(res, err.Error(), 500)
			return
		}
		session.Values["User"] = *user
		err = session.Save(req, res)
		if err != nil {
			http.Error(res, err.Error(), 500)
			return
		}

		// Redirect to the front page.
		http.Redirect(res, req, "/", 302)
	} else {
		webApp.RenderTemplate(&res, req, "login", data)
	}
}

// Validate validates the LoginForm.
func (form *LoginForm) Validate(db *Database) (user *User, formErrors FormErrors) {
	formErrors = make(FormErrors)
	if len(form.Login) == 0 {
		formErrors["Login"] = "A username or e-mail address is required."
	}
	if len(form.Password) == 0 {
		formErrors["Password"] = "A password is required."
	}

	// Return early if our username or password doesn't validate.
	if len(formErrors) > 0 {
		return
	}

	// Try and log the user in.
	user, err := db.LoginUser(form.Login, form.Password)
	if err != nil {
		formErrors["Flash"] = "Invalid username or password"
	}

	return
}

// NewLoginData creates a new LoginData that optionally contains prepopulated
// data from the request.
func NewLoginData(req *http.Request) (data *LoginData) {
	data = &LoginData{}

	if req != nil {
		data.Form = &LoginForm{
			Login:    req.PostFormValue("login"),
			Password: req.PostFormValue("password"),
		}
	} else {
		data.Form = &LoginForm{}
	}

	return
}
