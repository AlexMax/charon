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

package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"os"

	"github.com/AlexMax/charon"
	"github.com/go-ini/ini"
	"github.com/jawher/mow.cli"
)

const passwordLength = 12
const passwordLetters = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789"

func main() {
	cmd := cli.App("cmanage", "Manage a charon database")
	cmd.Command("adduser", "Add a user to the database", addUser)
	cmd.Run(os.Args)
}

func addUser(cmd *cli.Cmd) {
	cmd.Spec = "[-c] USERNAME EMAIL"
	configPath := cmd.StringOpt("c config", "charon.ini", "Path to the configuration file")
	username := cmd.StringArg("USERNAME", "", "Username of the new user")
	email := cmd.StringArg("EMAIL", "", "Email of the new user")

	cmd.Action = func() {
		config, err := ini.Load(*configPath)
		if err != nil {
			fmt.Print(err)
			os.Exit(1)
		}

		db, err := charon.NewDatabase(config)
		if err != nil {
			fmt.Print(err)
			os.Exit(1)
		}

		password := make([]byte, passwordLength)
		for i := range password {
			randomLetter, err := rand.Int(rand.Reader, big.NewInt(int64(len(passwordLetters))))
			if err != nil {
				fmt.Printf("crypto/rand.Int() error: %s", err.Error())
			}
			password[i] = passwordLetters[randomLetter.Uint64()]
		}
		sPassword := string(password)

		err = db.AddUser(*username, *email, sPassword)
		if err != nil {
			fmt.Print(err)
			os.Exit(1)
		}

		fmt.Print("User successfully added.\n")
		fmt.Printf("\tUsername: %s\n", *username)
		fmt.Printf("\tPassword: %s\n", sPassword)
	}
}
