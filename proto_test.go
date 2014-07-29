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

package charon

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
	expected := []byte("\x10\xCA\x03\xD0\x01\xFF\xFF\xFF\xFF\x04\x88\x88\x88\x88username\x00")

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
	valid := []byte("\x10\xCA\x03\xD0\x01\xFF\xFF\xFF\xFF\x04\x88\x88\x88\x88username\x00")

	var packet AuthNegotiate
	err := packet.UnmarshalBinary(valid)
	if err != nil {
		t.Errorf("%s", err.Error())
	}
	if 4294967295 != packet.session {
		t.Errorf("Session is %v instead of 4294967295", packet.session)
	}
	if !bytes.Equal([]byte{136, 136, 136, 136}, packet.salt) {
		t.Errorf("Salt is %v instead of [136 136 136 136]", packet.salt)
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
		[]byte("\x10\xCA\x03\xD0\x01\xFF\xFF\xFF\xFF\x04\x88\x88\x88\x88username"),
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

func TestServerEphemeralMarshall(t *testing.T) {
	expected := []byte("\x02\xCA\x03\xD0\xFF\xFF\xFF\xFF\x04\x00\x88\x88\x88\x88")

	var packet ServerEphemeral
	packet.session = 4294967295
	packet.ephemeral = []byte("\x88\x88\x88\x88")

	actual, err := packet.MarshalBinary()
	if err != nil {
		t.Errorf("%s", err.Error())
	}
	if !bytes.Equal(expected, actual) {
		t.Errorf("Expected: %v Actual: %v", expected, actual)
	}
}

func TestServerEphemeralUnmarshall(t *testing.T) {
	valid := []byte("\x02\xCA\x03\xD0\xFF\xFF\xFF\xFF\x04\x00\x88\x88\x88\x88")

	var packet ServerEphemeral
	err := packet.UnmarshalBinary(valid)
	if err != nil {
		t.Errorf("%s", err.Error())
	}
	if 4294967295 != packet.session {
		t.Errorf("Session is %v instead of 4294967295", packet.session)
	}
	if !bytes.Equal([]byte{136, 136, 136, 136}, packet.ephemeral) {
		t.Errorf("Ephemeral is %v instead of [136 136 136 136]", packet.ephemeral)
	}
}

func TestServerEphemeralUnmarshallErrors(t *testing.T) {
	errors := [][]byte{
		// Too short
		[]byte("\x02\xCA"),
		// Incorrect header
		[]byte("\x02\xCA\x03\xD1"),
		// Incorrect ephemeral size
		[]byte("\x02\xCA\x03\xD0\xFF\xFF\xFF\xFF\xEE\xEE\x88\x88\x88\x88"),
	}

	var err error
	var packet ServerEphemeral
	for _, test := range errors {
		err = packet.UnmarshalBinary(test)
		if err == nil {
			t.Errorf("%v was incorrectly parsed as valid", test)
		}
	}
}

func TestAuthEphemeralMarshall(t *testing.T) {
	expected := []byte("\x20\xCA\x03\xD0\xFF\xFF\xFF\xFF\x04\x00\x88\x88\x88\x88")

	var packet AuthEphemeral
	packet.session = 4294967295
	packet.ephemeral = []byte("\x88\x88\x88\x88")

	actual, err := packet.MarshalBinary()
	if err != nil {
		t.Errorf("%s", err.Error())
	}
	if !bytes.Equal(expected, actual) {
		t.Errorf("Expected: %v Actual: %v", expected, actual)
	}
}

func TestAuthEphemeralUnmarshall(t *testing.T) {
	valid := []byte("\x20\xCA\x03\xD0\xFF\xFF\xFF\xFF\x04\x00\x88\x88\x88\x88")

	var packet AuthEphemeral
	err := packet.UnmarshalBinary(valid)
	if err != nil {
		t.Errorf("%s", err.Error())
	}
	if 4294967295 != packet.session {
		t.Errorf("Session is %v instead of 4294967295", packet.session)
	}
	if !bytes.Equal([]byte{136, 136, 136, 136}, packet.ephemeral) {
		t.Errorf("Ephemeral is %v instead of [136 136 136 136]", packet.ephemeral)
	}
}

func TestAuthEphemeralUnmarshallErrors(t *testing.T) {
	errors := [][]byte{
		// Too short
		[]byte("\x20\xCA"),
		// Incorrect header
		[]byte("\x20\xCA\x03\xD1"),
		// Incorrect ephemeral size
		[]byte("\x20\xCA\x03\xD0\xFF\xFF\xFF\xFF\xEE\xEE\x88\x88\x88\x88"),
	}

	var err error
	var packet AuthEphemeral
	for _, test := range errors {
		err = packet.UnmarshalBinary(test)
		if err == nil {
			t.Errorf("%v was incorrectly parsed as valid", test)
		}
	}
}

func TestServerProofMarshall(t *testing.T) {
	expected := []byte("\x03\xCA\x03\xD0\xFF\xFF\xFF\xFF\x04\x00\x88\x88\x88\x88")

	var packet ServerProof
	packet.session = 4294967295
	packet.proof = []byte("\x88\x88\x88\x88")

	actual, err := packet.MarshalBinary()
	if err != nil {
		t.Errorf("%s", err.Error())
	}
	if !bytes.Equal(expected, actual) {
		t.Errorf("Expected: %v Actual: %v", expected, actual)
	}
}

func TestServerProofUnmarshall(t *testing.T) {
	valid := []byte("\x03\xCA\x03\xD0\xFF\xFF\xFF\xFF\x04\x00\x88\x88\x88\x88")

	var packet ServerProof
	err := packet.UnmarshalBinary(valid)
	if err != nil {
		t.Errorf("%s", err.Error())
	}
	if 4294967295 != packet.session {
		t.Errorf("Session is %v instead of 4294967295", packet.session)
	}
	if !bytes.Equal([]byte{136, 136, 136, 136}, packet.proof) {
		t.Errorf("Ephemeral is %v instead of [136 136 136 136]", packet.proof)
	}
}

func TestServerProofUnmarshallErrors(t *testing.T) {
	errors := [][]byte{
		// Too short
		[]byte("\x03\xCA"),
		// Incorrect header
		[]byte("\x03\xCA\x03\xD1"),
		// Incorrect proof size
		[]byte("\x03\xCA\x03\xD0\xFF\xFF\xFF\xFF\xEE\xEE\x88\x88\x88\x88"),
	}

	var err error
	var packet ServerProof
	for _, test := range errors {
		err = packet.UnmarshalBinary(test)
		if err == nil {
			t.Errorf("%v was incorrectly parsed as valid", test)
		}
	}
}

func TestAuthProofMarshall(t *testing.T) {
	expected := []byte("\x30\xCA\x03\xD0\xFF\xFF\xFF\xFF\x04\x00\x88\x88\x88\x88")

	var packet AuthProof
	packet.session = 4294967295
	packet.proof = []byte("\x88\x88\x88\x88")

	actual, err := packet.MarshalBinary()
	if err != nil {
		t.Errorf("%s", err.Error())
	}
	if !bytes.Equal(expected, actual) {
		t.Errorf("Expected: %v Actual: %v", expected, actual)
	}
}

func TestAuthProofUnmarshall(t *testing.T) {
	valid := []byte("\x30\xCA\x03\xD0\xFF\xFF\xFF\xFF\x04\x00\x88\x88\x88\x88")

	var packet AuthProof
	err := packet.UnmarshalBinary(valid)
	if err != nil {
		t.Errorf("%s", err.Error())
	}
	if 4294967295 != packet.session {
		t.Errorf("Session is %v instead of 4294967295", packet.session)
	}
	if !bytes.Equal([]byte{136, 136, 136, 136}, packet.proof) {
		t.Errorf("Ephemeral is %v instead of [136 136 136 136]", packet.proof)
	}
}

func TestAuthProofUnmarshallErrors(t *testing.T) {
	errors := [][]byte{
		// Too short
		[]byte("\x30\xCA"),
		// Incorrect header
		[]byte("\x30\xCA\x03\xD1"),
		// Incorrect proof size
		[]byte("\x30\xCA\x03\xD0\xFF\xFF\xFF\xFF\xEE\xEE\x88\x88\x88\x88"),
	}

	var err error
	var packet AuthProof
	for _, test := range errors {
		err = packet.UnmarshalBinary(test)
		if err == nil {
			t.Errorf("%v was incorrectly parsed as valid", test)
		}
	}
}
