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
	"encoding/binary"
	"errors"
	"strings"
)

const (
	PROTOCOL_VERSION uint8  = 1
	SERVER_NEGOTIATE uint32 = 0xD003CA01
	AUTH_NEGOTIATE   uint32 = 0xD003CA10
	SERVER_EPHEMERAL uint32 = 0xD003CA02
	AUTH_EPHEMERAL   uint32 = 0xD003CA20
	SERVER_PROOF     uint32 = 0xD003CA03
	AUTH_PROOF       uint32 = 0xD003CA30
	ERROR_USER       uint32 = 0xD003CAFF
	ERROR_SESSION    uint32 = 0xD003CAEE
)

type ServerNegotiate struct {
	username string
}

func (packet *ServerNegotiate) MarshalBinary() (data []byte, err error) {
	var buffer bytes.Buffer

	err = binary.Write(&buffer, binary.LittleEndian, SERVER_NEGOTIATE)
	if err != nil {
		return
	}

	err = binary.Write(&buffer, binary.LittleEndian, PROTOCOL_VERSION)
	if err != nil {
		return
	}

	buffer.WriteString(packet.username)
	buffer.WriteByte(0)

	data = buffer.Bytes()
	return
}

func (packet *ServerNegotiate) UnmarshalBinary(data []byte) (err error) {
	buffer := bytes.NewBuffer(data)

	var header uint32
	err = binary.Read(buffer, binary.LittleEndian, &header)
	if err != nil {
		return
	}
	if header != SERVER_NEGOTIATE {
		return errors.New("packet has incorrect header")
	}

	var version uint8
	err = binary.Read(buffer, binary.LittleEndian, &version)
	if err != nil {
		return
	}
	if version != PROTOCOL_VERSION {
		return errors.New("packet has unknown version")
	}

	username, err := buffer.ReadString(0)
	if err != nil {
		return
	}

	packet.username = strings.TrimRight(username, "\x00")
	return
}

type AuthNegotiate struct {
	session  uint32
	salt     []byte
	username string
}

func (packet *AuthNegotiate) MarshalBinary() (data []byte, err error) {
	var buffer bytes.Buffer

	err = binary.Write(&buffer, binary.LittleEndian, AUTH_NEGOTIATE)
	if err != nil {
		return
	}

	err = binary.Write(&buffer, binary.LittleEndian, PROTOCOL_VERSION)
	if err != nil {
		return
	}

	err = binary.Write(&buffer, binary.LittleEndian, packet.session)
	if err != nil {
		return
	}

	err = binary.Write(&buffer, binary.LittleEndian, uint8(len(packet.salt)))
	if err != nil {
		return
	}

	err = binary.Write(&buffer, binary.LittleEndian, packet.salt)
	if err != nil {
		return
	}

	buffer.WriteString(packet.username)
	buffer.WriteByte(0)

	data = buffer.Bytes()
	return
}

func (packet *AuthNegotiate) UnmarshalBinary(data []byte) (err error) {
	buffer := bytes.NewBuffer(data)

	var header uint32
	err = binary.Read(buffer, binary.LittleEndian, &header)
	if err != nil {
		return
	}
	if header != AUTH_NEGOTIATE {
		return errors.New("packet has incorrect header")
	}

	var version uint8
	err = binary.Read(buffer, binary.LittleEndian, &version)
	if err != nil {
		return
	}
	if version != PROTOCOL_VERSION {
		return errors.New("packet has unknown version")
	}

	var session uint32
	err = binary.Read(buffer, binary.LittleEndian, &session)
	if err != nil {
		return
	}

	var saltlen uint8
	err = binary.Read(buffer, binary.LittleEndian, &saltlen)
	if err != nil {
		return
	}

	var salt = make([]byte, saltlen)
	err = binary.Read(buffer, binary.LittleEndian, &salt)
	if err != nil {
		return
	}

	username, err := buffer.ReadString(0)
	if err != nil {
		return
	}

	packet.session = session
	packet.salt = salt
	packet.username = strings.TrimRight(username, "\x00")
	return
}
