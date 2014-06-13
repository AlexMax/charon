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

package auth

import (
	"encoding/binary"
	"errors"
	"log"
	"net"

	"github.com/AlexMax/charon/proto"
	_ "github.com/tadglines/go-pkgs/crypto/srp"
)

func New() (err error) {
	listenaddr, err := net.ResolveUDPAddr("udp", ":16666")
	if err != nil {
		return
	}

	conn, err := net.ListenUDP("udp", listenaddr)
	if err != nil {
		return
	}

	for {
		message := make([]byte, 1024)

		msglen, msgaddr, msgerr := conn.ReadFromUDP(message)
		if msgerr != nil {
			continue
		}

		go loggedRouter(message[:msglen], msgaddr)
	}
}

func loggedRouter(message []byte, source *net.UDPAddr) {
	res, err := router(message, source)
	if err != nil {
		log.Printf("[DEBUG] %s", err.Error())
	}
}

func router(message []byte, source *net.UDPAddr) (err error) {
	if len(message) < 4 {
		err = errors.New("Message is too small")
		return
	}

	header := binary.LittleEndian.Uint32(message[:4])
	switch header {
	case proto.SERVER_NEGOTIATE:
		var packet proto.ServerNegotiate
		err := packet.UnmarshalBinary(message)
		if err != nil {
			return
		}
		err := negotiate(&packet)
	case proto.SERVER_EPHEMERAL:
		var packet proto.ServerEphemeral
		err := packet.UnmarshalBinary(message)
		if err != nil {
			return
		}
		err := ephemeral(&packet)
	case proto.SERVER_PROOF:
		var packet proto.ServerProof
		err := packet.UnmarshalBinary(message)
		if err != nil {
			return
		}
		err := proof(&packet)
	}
}

func negotiate(packet *proto.ServerNegotiate) (err error) {

}

func ephemeral(packet *proto.ServerEphemeral) (err error) {

}

func proof(packet *proto.ServerProof) (err error) {

}
