package charon

import (
	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
)

type Database struct {
	db *sqlx.DB
}

func NewDatabase() (database *Database, err error) {
	db, err := sqlx.Connect("sqlite3", ":memory:")
	if err != nil {
		return
	}

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

// Try to find a specific user by name or email address.
func (self *Database) FindUser(username string) (user *User, err error) {
	/*
		user = []User{}
		username = ToLower(username)
		self.db.Select(&user, "SELECT * FROM users WHERE username = $1 OR email = $1 LIMIT 1", username)
	*/

	return
}
