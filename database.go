/*
 *  Charon: A game authentication server
 *  Copyright (C) 2014-2015  Alex Mayfield <alexmax2742@gmail.com>
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
	"crypto/sha256"
	"strings"
	"sync"

	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
	"github.com/tadglines/go-pkgs/crypto/srp"
)

type Database struct {
	db    *sqlx.DB
	mutex sync.Mutex
}

// Schema for sqlite3.
var schema = `
CREATE TABLE IF NOT EXISTS users(
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	username TEXT UNIQUE NOT NULL,
	email TEXT NOT NULL,
	verifier BLOB NOT NULL,
	salt BLOB NOT NULL,
	access TEXT NOT NULL,
	active INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS profiles(
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	user_id INTEGER,
	clan TEXT,
	contactinfo TEXT,
	country TEXT,
	gravatar TEXT,
	location TEXT,
	message TEXT,
	username TEXT,
	visible INTEGER,
	visible_lastplayed INTEGER,
	FOREIGN KEY(user_id) REFERENCES users(id)
);`

func NewDatabase() (database *Database, err error) {
	// Create a database connection.
	db, err := sqlx.Connect("sqlite3", ":memory:")
	if err != nil {
		return
	}

	// Create the database schema.
	_ = db.MustExec("PRAGMA foreign_keys = ON;")
	_ = db.MustExec(schema)

	database = new(Database)
	database.db = db
	return
}

// A representation of a user.
type User struct {
	Id       uint
	Username string
	Email    string
	Verifier []byte
	Salt     []byte
	Access   string
	Active   bool
}

const (
	UserAccessUnverified string = "UNVERIFIED"
	UserAccessUser       string = "USER"
	UserAccessOp         string = "OP"
	UserAccessMaster     string = "MASTER"
	UserAccessOwner      string = "OWNER"
)

// Add a new user
func (self *Database) AddUser(username string, email string, password string) (err error) {
	srp, err := srp.NewSRP("rfc5054.2048", sha256.New, nil)
	if err != nil {
		return err
	}

	user := new(User)
	user.Username = username
	user.Email = email
	user.Access = UserAccessUnverified
	user.Active = false

	user.Salt, user.Verifier, err = srp.ComputeVerifier([]byte(password))
	if err != nil {
		return err
	}

	self.mutex.Lock()
	_, err = self.db.NamedExec("INSERT INTO users (Username, Email, Verifier, Salt, Access, Active) VALUES (:username, :email, :verifier, :salt, :access, :active)", user)
	self.mutex.Unlock()
	return
}

// Try to find a specific user by name or email address.
func (self *Database) FindUser(username string) (user *User, err error) {
	user = &User{}
	self.mutex.Lock()
	err = self.db.Get(user, "SELECT * FROM users WHERE username LIKE $1 OR email LIKE $1", strings.ToLower(username))
	self.mutex.Unlock()
	return
}

// A representation of a user's profile.
type Profile struct {
	Id                 uint
	User_id            uint
	Clan               string
	Contactinfo        string
	Country            string
	Gravatar           string
	Location           string
	Message            string
	Username           string
	Visible            bool
	Visible_lastplayed bool
}
