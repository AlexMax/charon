/*
 *  Charon: A game authentication server
 *  Copyright (C) 2014  Alex Mayfield <alexmax2742@gmail.com>
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

package proto

import (
	"bytes"
	"testing"
)

func TestServerNegotiateMarshall(t *testing.T) {
	expected := []byte("\x01\xCA\x03\xD0\x01username\x00")

	var packet ServerNegotiate
	packet.username = "username"

	actual, err := packet.MarshalBinary()
	if err != nil {
		t.Errorf("%s", err.Error())
	}
	if !bytes.Equal(expected, actual) {
		t.Errorf("Expected: %v Actual: %v", expected, actual)
	}
}

func TestServerNegotiateUnmarshall(t *testing.T) {
	valid := []byte("\x01\xCA\x03\xD0\x01username\x00")

	var packet ServerNegotiate
	err := packet.UnmarshalBinary(valid)
	if err != nil {
		t.Errorf("%s", err.Error())
	}
	if "username" != packet.username {
		t.Errorf("Username is %v instead of username", packet.username)
	}
}

func TestServerNegotiateUnmarshallErrors(t *testing.T) {
	errors := [][]byte{
		// Too short
		[]byte("\x01\xCA"),
		// Incorrect header
		[]byte("\x01\xCA\x03\x00"),
		// Incorrect protocol version
		[]byte("\x01\xCA\x03\xD0\xFF"),
		// No null at end of username
		[]byte("\x01\xCA\x03\xD0\x01username"),
	}

	var err error
	var packet ServerNegotiate
	for _, test := range errors {
		err = packet.UnmarshalBinary(test)
		if err == nil {
			t.Errorf("%v was incorrectly parsed as valid", test)
		}
	}
}

func TestAuthNegotiateMarshall(t *testing.T) {
	expected := []byte("\x10\xCA\x03\xD0\x01\xff\xff\xff\xff\x04\x88\x88\x88\x88username\x00")

	var packet AuthNegotiate
	packet.session = 4294967295
	packet.salt = []byte("\x88\x88\x88\x88")
	packet.username = "username"

	actual, err := packet.MarshalBinary()
	if err != nil {
		t.Errorf("%s", err.Error())
	}
	if !bytes.Equal(expected, actual) {
		t.Errorf("Expected: %v Actual: %v", expected, actual)
	}
}

func TestAuthNegotiateUnmarshall(t *testing.T) {
	valid := []byte("\x10\xCA\x03\xD0\x01\xff\xff\xff\xff\x04\x88\x88\x88\x88username\x00")

	var packet AuthNegotiate
	err := packet.UnmarshalBinary(valid)
	if err != nil {
		t.Errorf("%s", err.Error())
	}
	if 4294967295 != packet.session {
		t.Errorf("Session is %v instead of 4294967295", packet.session)
	}
	if !bytes.Equal([]byte{136, 136, 136, 136}, packet.salt) {
		t.Errorf("Session is %v instead of [136 136 136 136]", packet.salt)
	}
	if "username" != packet.username {
		t.Errorf("Username is %v instead of username", packet.username)
	}
}

func TestAuthNegotiateUnmarshallErrors(t *testing.T) {
	errors := [][]byte{
		// Too short
		[]byte("\x10\xCA"),
		// Incorrect header
		[]byte("\x10\xCA\x03\xD1"),
		// Incorrect protocol version
		[]byte("\x10\xCA\x03\xD0\xFF"),
		// Incorrect salt size
		[]byte("\x10\xCA\x03\xD0\x01\xFF\xFF\xFF\xFF\xEE\x88\x88\x88\x88"),
		// Missing username null terminator
		[]byte("\x10\xCA\x03\xD0\x01\xff\xff\xff\xff\x04\x88\x88\x88\x88username"),
	}

	var err error
	var packet ServerNegotiate
	for _, test := range errors {
		err = packet.UnmarshalBinary(test)
		if err == nil {
			t.Errorf("%v was incorrectly parsed as valid", test)
		}
	}
}
