package charon

import (
	"strings"

	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
)

type Database struct {
	db *sqlx.DB
}

// Schema for sqlite3.
var schema = `
CREATE TABLE IF NOT EXISTS users(
	id INT PRIMARY KEY,
	username TEXT,
	email TEXT,
	verifier BLOB,
	salt BLOB,
	access TEXT,
	active INTEGER
);
CREATE TABLE IF NOT EXISTS profiles(
	id INT PRIMARY KEY,
	user_id INT,
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
	id       uint
	username string
	email    string
	verifier []byte
	salt     []byte
	access   string
	active   bool
}

// Try to find a specific user by name or email address.
func (self *Database) FindUser(username string) (user *User, err error) {
	user = &User{}
	err = self.db.Get(&user, "SELECT * FROM users WHERE username LIKE $1 OR email LIKE $1", strings.ToLower(username))
	return
}

// A representation of a user's profile.
type Profile struct {
	id                 uint
	user_id            uint
	clan               string
	contactinfo        string
	country            string
	gravatar           string
	location           string
	message            string
	username           string
	visible            bool
	visible_lastplayed bool
}
