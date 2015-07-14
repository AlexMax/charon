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
	"encoding/binary"
	"errors"
	"strings"
)

// Protocol constants.
const (
	CharonServerNegotiate uint32 = 0xD003CA01
	CharonAuthNegotiate   uint32 = 0xD003CA10
	CharonServerEphemeral uint32 = 0xD003CA02
	CharonAuthEphemeral   uint32 = 0xD003CA20
	CharonServerProof     uint32 = 0xD003CA03
	CharonAuthProof       uint32 = 0xD003CA30
	CharonErrorUser       uint32 = 0xD003CAFF
	CharonErrorSession    uint32 = 0xD003CAEE
)

// ServerNegotiate is a connection negotiation packet that is sent from the game
// server to the auth server.
type ServerNegotiate struct {
	version       uint8
	clientSession uint32
	username      string
}

// MarshalBinary marshalls a ServerNegotiate from binary data.
func (packet *ServerNegotiate) MarshalBinary() (data []byte, err error) {
	var buffer bytes.Buffer

	binary.Write(&buffer, binary.LittleEndian, CharonServerNegotiate)
	binary.Write(&buffer, binary.LittleEndian, packet.version)
	binary.Write(&buffer, binary.LittleEndian, packet.clientSession)
	buffer.WriteString(packet.username)
	buffer.WriteByte(0)

	data = buffer.Bytes()
	return
}

// UnmarshalBinary unmarshalls a ServerNegotiate to binary data.
func (packet *ServerNegotiate) UnmarshalBinary(data []byte) (err error) {
	buffer := bytes.NewBuffer(data)

	var header uint32
	err = binary.Read(buffer, binary.LittleEndian, &header)
	if err != nil {
		return
	}
	if header != CharonServerNegotiate {
		return errors.New("packet has incorrect header")
	}

	var version uint8
	err = binary.Read(buffer, binary.LittleEndian, &version)
	if err != nil {
		return
	}
	if version == 1 {
		return errors.New("protocol version 1 is not supported")
	} else if version != 2 {
		return errors.New("packet has unknown protocol version")
	}

	var clientSession uint32
	err = binary.Read(buffer, binary.LittleEndian, &clientSession)
	if err != nil {
		return
	}

	username, err := buffer.ReadString(0)
	if err != nil {
		return
	}

	packet.version = version
	packet.clientSession = clientSession
	packet.username = strings.TrimRight(username, "\x00")
	return
}

// AuthNegotiate is a connection negotiation packet that is sent from the auth
// server to the game server.
type AuthNegotiate struct {
	version       uint8
	clientSession uint32
	session       uint32
	salt          []byte
	username      string
}

// MarshalBinary marshalls an AuthNegotiate from binary data.
func (packet *AuthNegotiate) MarshalBinary() (data []byte, err error) {
	var buffer bytes.Buffer

	binary.Write(&buffer, binary.LittleEndian, CharonAuthNegotiate)
	binary.Write(&buffer, binary.LittleEndian, packet.version)
	binary.Write(&buffer, binary.LittleEndian, packet.clientSession)
	binary.Write(&buffer, binary.LittleEndian, packet.session)
	binary.Write(&buffer, binary.LittleEndian, uint8(len(packet.salt)))
	binary.Write(&buffer, binary.LittleEndian, packet.salt)
	buffer.WriteString(packet.username)
	buffer.WriteByte(0)

	data = buffer.Bytes()
	return
}

// UnmarshalBinary unmarshalls an AuthNegotiate to binary data.
func (packet *AuthNegotiate) UnmarshalBinary(data []byte) (err error) {
	buffer := bytes.NewBuffer(data)

	var header uint32
	err = binary.Read(buffer, binary.LittleEndian, &header)
	if err != nil {
		return
	}
	if header != CharonAuthNegotiate {
		return errors.New("packet has incorrect header")
	}

	var version uint8
	err = binary.Read(buffer, binary.LittleEndian, &version)
	if err != nil {
		return
	}
	if version == 1 {
		return errors.New("protocol version 1 is not supported")
	} else if version != 2 {
		return errors.New("packet has unknown protocol version")
	}

	var clientSession uint32
	err = binary.Read(buffer, binary.LittleEndian, &clientSession)
	if err != nil {
		return
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

	packet.version = version
	packet.clientSession = clientSession
	packet.session = session
	packet.salt = salt
	packet.username = strings.TrimRight(username, "\x00")
	return
}

// ServerEphemeral contains an SRP ephemeral value sent from the game server to
// the auth server.
type ServerEphemeral struct {
	session   uint32
	ephemeral []byte
}

// MarshalBinary marshalls a ServerEphemeral from binary data.
func (packet *ServerEphemeral) MarshalBinary() (data []byte, err error) {
	var buffer bytes.Buffer

	err = binary.Write(&buffer, binary.LittleEndian, CharonServerEphemeral)
	if err != nil {
		return
	}

	err = binary.Write(&buffer, binary.LittleEndian, packet.session)
	if err != nil {
		return
	}

	err = binary.Write(&buffer, binary.LittleEndian, uint16(len(packet.ephemeral)))
	if err != nil {
		return
	}

	err = binary.Write(&buffer, binary.LittleEndian, packet.ephemeral)
	if err != nil {
		return
	}

	data = buffer.Bytes()
	return
}

// UnmarshalBinary unmarshalls a ServerEphemeral to binary data.
func (packet *ServerEphemeral) UnmarshalBinary(data []byte) (err error) {
	buffer := bytes.NewBuffer(data)

	var header uint32
	err = binary.Read(buffer, binary.LittleEndian, &header)
	if err != nil {
		return
	}
	if header != CharonServerEphemeral {
		return errors.New("packet has incorrect header")
	}

	var session uint32
	err = binary.Read(buffer, binary.LittleEndian, &session)
	if err != nil {
		return
	}

	var ephemerallen uint16
	err = binary.Read(buffer, binary.LittleEndian, &ephemerallen)
	if err != nil {
		return
	}

	var ephemeral = make([]byte, ephemerallen)
	err = binary.Read(buffer, binary.LittleEndian, &ephemeral)
	if err != nil {
		return
	}

	packet.session = session
	packet.ephemeral = ephemeral
	return
}

// AuthEphemeral contains an SRP ephemeral value sent from the auth server to
// the game server.
type AuthEphemeral struct {
	session   uint32
	ephemeral []byte
}

// MarshalBinary marshalls an AuthEphemeral from binary data.
func (packet *AuthEphemeral) MarshalBinary() (data []byte, err error) {
	var buffer bytes.Buffer

	err = binary.Write(&buffer, binary.LittleEndian, CharonAuthEphemeral)
	if err != nil {
		return
	}

	err = binary.Write(&buffer, binary.LittleEndian, packet.session)
	if err != nil {
		return
	}

	err = binary.Write(&buffer, binary.LittleEndian, uint16(len(packet.ephemeral)))
	if err != nil {
		return
	}

	err = binary.Write(&buffer, binary.LittleEndian, packet.ephemeral)
	if err != nil {
		return
	}

	data = buffer.Bytes()
	return
}

// UnmarshalBinary unmarshalls an AuthEphemeral to binary data.
func (packet *AuthEphemeral) UnmarshalBinary(data []byte) (err error) {
	buffer := bytes.NewBuffer(data)

	var header uint32
	err = binary.Read(buffer, binary.LittleEndian, &header)
	if err != nil {
		return
	}
	if header != CharonAuthEphemeral {
		return errors.New("packet has incorrect header")
	}

	var session uint32
	err = binary.Read(buffer, binary.LittleEndian, &session)
	if err != nil {
		return
	}

	var ephemerallen uint16
	err = binary.Read(buffer, binary.LittleEndian, &ephemerallen)
	if err != nil {
		return
	}

	var ephemeral = make([]byte, ephemerallen)
	err = binary.Read(buffer, binary.LittleEndian, &ephemeral)
	if err != nil {
		return
	}

	packet.session = session
	packet.ephemeral = ephemeral
	return
}

// ServerProof contains a SRP proof value sent from the game server to
// the auth server.
type ServerProof struct {
	session uint32
	proof   []byte
}

// MarshalBinary marshalls a ServerProof from binary data.
func (packet *ServerProof) MarshalBinary() (data []byte, err error) {
	var buffer bytes.Buffer

	err = binary.Write(&buffer, binary.LittleEndian, CharonServerProof)
	if err != nil {
		return
	}

	err = binary.Write(&buffer, binary.LittleEndian, packet.session)
	if err != nil {
		return
	}

	err = binary.Write(&buffer, binary.LittleEndian, uint16(len(packet.proof)))
	if err != nil {
		return
	}

	err = binary.Write(&buffer, binary.LittleEndian, packet.proof)
	if err != nil {
		return
	}

	data = buffer.Bytes()
	return
}

// UnmarshalBinary unmarshalls a ServerProof to binary data.
func (packet *ServerProof) UnmarshalBinary(data []byte) (err error) {
	buffer := bytes.NewBuffer(data)

	var header uint32
	err = binary.Read(buffer, binary.LittleEndian, &header)
	if err != nil {
		return
	}
	if header != CharonServerProof {
		return errors.New("packet has incorrect header")
	}

	var session uint32
	err = binary.Read(buffer, binary.LittleEndian, &session)
	if err != nil {
		return
	}

	var prooflen uint16
	err = binary.Read(buffer, binary.LittleEndian, &prooflen)
	if err != nil {
		return
	}

	var proof = make([]byte, prooflen)
	err = binary.Read(buffer, binary.LittleEndian, &proof)
	if err != nil {
		return
	}

	packet.session = session
	packet.proof = proof
	return
}

// AuthProof contains a SRP proof value sent from the auth server to
// the game server.
type AuthProof struct {
	session uint32
	proof   []byte
}

// MarshalBinary marshalls an AuthProof from binary data.
func (packet *AuthProof) MarshalBinary() (data []byte, err error) {
	var buffer bytes.Buffer

	err = binary.Write(&buffer, binary.LittleEndian, CharonAuthProof)
	if err != nil {
		return
	}

	err = binary.Write(&buffer, binary.LittleEndian, packet.session)
	if err != nil {
		return
	}

	err = binary.Write(&buffer, binary.LittleEndian, uint16(len(packet.proof)))
	if err != nil {
		return
	}

	err = binary.Write(&buffer, binary.LittleEndian, packet.proof)
	if err != nil {
		return
	}

	data = buffer.Bytes()
	return
}

// UnmarshalBinary unmarshalls an AuthProof to binary data.
func (packet *AuthProof) UnmarshalBinary(data []byte) (err error) {
	buffer := bytes.NewBuffer(data)

	var header uint32
	err = binary.Read(buffer, binary.LittleEndian, &header)
	if err != nil {
		return
	}
	if header != CharonAuthProof {
		return errors.New("packet has incorrect header")
	}

	var session uint32
	err = binary.Read(buffer, binary.LittleEndian, &session)
	if err != nil {
		return
	}

	var prooflen uint16
	err = binary.Read(buffer, binary.LittleEndian, &prooflen)
	if err != nil {
		return
	}

	var proof = make([]byte, prooflen)
	err = binary.Read(buffer, binary.LittleEndian, &proof)
	if err != nil {
		return
	}

	packet.session = session
	packet.proof = proof
	return
}
