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

type LoginForm struct {
	Login    string
	Password string
}

type FormErrors map[string]string

// Validate validates the given login form.
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
