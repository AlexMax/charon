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

package main

import (
	"log"

	"github.com/AlexMax/charon"
)

func main() {
	log.Print("Starting Charon...")

	// Construct application.
	authApp, err := charon.NewAuthApp()
	if err != nil {
		log.Fatal(err)
	}

	// Start the application server.
	log.Fatal(authApp.ListenAndServe(":16666"))
}
