/*
 *  Charon: A game authentication server
 *  Copyright (C) 2014-2016  Alex Mayfield <alexmax2742@gmail.com>
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
	"time"

	"github.com/AlexMax/charon/srp"
	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3" // Database driver
)

// Database is an instance of our database connection and all necessary state
// used to manage said instance.
type Database struct {
	db    *sqlx.DB
	mutex sync.Mutex
}

// Schema for sqlite3.
const schema = `
CREATE TABLE IF NOT EXISTS Users(
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	username VARCHAR(255),
	email VARCHAR(255),
	verifier BLOB,
	salt BLOB,
	access TEXT,
	active TINYINT(1),
	createdAt DATETIME NOT NULL,
	updatedAt DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS Profiles(
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	clan VARCHAR(255),
	clantag VARCHAR(255),
	contactinfo VARCHAR(255),
	country VARCHAR(255),
	gravatar TEXT,
	location VARCHAR(255),
	message VARCHAR(255),
	username VARCHAR(255),
	visible TINYINT(1) DEFAULT 1,
	visible_lastseen TINYINT(1) DEFAULT 1,
	createdAt DATETIME NOT NULL,
	updatedAt DATETIME NOT NULL,
	UserId INTEGER
);`

// NewDatabase creates a new Database instance.
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

// User is a representation of the `User` table in the database.
type User struct {
	ID        uint
	Username  string
	Email     string
	Verifier  []byte
	Salt      []byte
	Access    string
	Active    bool
	CreatedAt time.Time `db:"createdAt"`
	UpdatedAt time.Time `db:"updatedAt"`
}

// User access constants.
const (
	UserAccessUnverified string = "UNVERIFIED"
	UserAccessUser       string = "USER"
	UserAccessOp         string = "OP"
	UserAccessMaster     string = "MASTER"
	UserAccessOwner      string = "OWNER"
)

// AddUser adds a new user.
func (database *Database) AddUser(username string, email string, password string) (err error) {
	srp, err := srp.NewSRP("rfc5054.2048", sha256.New, nil)
	if err != nil {
		return err
	}

	user := new(User)
	user.Username = username
	user.Email = email
	user.Access = UserAccessUnverified
	user.Active = false
	user.CreatedAt = time.Now()
	user.UpdatedAt = time.Now()

	user.Salt, user.Verifier, err = srp.ComputeVerifier([]byte(username), []byte(password))
	if err != nil {
		return err
	}

	database.mutex.Lock()
	_, err = database.db.NamedExec("INSERT INTO Users (Username, Email, Verifier, Salt, Access, Active, createdAt, updatedAt) VALUES (:username, :email, :verifier, :salt, :access, :active, :createdAt, :updatedAt)", user)
	database.mutex.Unlock()
	return
}

// FindUser tries to find a specific user by name or email address.
func (database *Database) FindUser(username string) (user *User, err error) {
	user = &User{}
	database.mutex.Lock()
	err = database.db.Get(user, "SELECT * FROM users WHERE username LIKE $1 OR email LIKE $1", strings.ToLower(username))
	database.mutex.Unlock()
	return
}

// Profile is representation of the `profile` table in the database.
type Profile struct {
	ID                 uint
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
