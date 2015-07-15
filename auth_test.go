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
	"net"
	"testing"
)

func TestRouterShortMessage(t *testing.T) {
	addr, _ := net.ResolveUDPAddr("udp4", "127.0.0.1:16667")
	req := request{addr, []byte("\x01")}

	app, err := NewAuthApp()
	_, err = app.router(&req)
	if err == nil {
		t.Errorf("%v was incorrectly routed as valid request", req)
	}
}

func TestRouterHandleNegotiate(t *testing.T) {
	// UDP sender
	addr, err := net.ResolveUDPAddr("udp4", "127.0.0.1:16667")

	// Assemble packet
	var packet ServerNegotiate
	packet.username = "username"
	packet.version = 2
	packet.clientSession = 4293844428
	actual, _ := packet.MarshalBinary()

	// Create auth app with fixture
	app, err := NewAuthApp()
	if err != nil {
		t.Errorf("%s", err.Error())
	}

	err = app.database.AddUser("username", "charontest@mailinator.com", "password")
	if err != nil {
		t.Errorf("%s", err.Error())
	}

	// Assemble UDP request
	req := request{addr, actual}
	route, err := app.router(&req)
	if err != nil {
		t.Errorf("Request was incorrectly routed (%v)", err)
	}

	// Route request
	res, err := route(&req)
	if err != nil {
		t.Errorf("Route returned an error (%v)", err)
	}

	// Unmarshall response
	var resPacket AuthNegotiate
	err = resPacket.UnmarshalBinary(res.message)
	if err != nil {
		t.Errorf("Response did not unmarshall correctly")
	}
	if resPacket.username != packet.username {
		t.Errorf("Incorrect username")
	}
	if resPacket.version != 2 {
		t.Errorf("Incorrect version")
	}
	if resPacket.clientSession != packet.clientSession {
		t.Errorf("Incorrect clientSession")
	}
}
