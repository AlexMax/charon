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
	"encoding/binary"
	"errors"
	"log"
	"net"
)

type request struct {
	address *net.UDPAddr
	message []byte
}

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
			log.Printf("[ERROR] %s", err.Error())
			continue
		}

		req := request{msgaddr, message[:msglen]}
		go loggedRouter(&req)
	}
}

func loggedRouter(req *request) {
	err := router(req)
	if err != nil {
		log.Printf("[DEBUG] %s", err.Error())
	}
}

func router(req *request) (err error) {
	if len(req.message) < 4 {
		err = errors.New("Message is too small")
		return
	}

	// Route the message to the appropriate handler.
	header := binary.LittleEndian.Uint32(req.message[:4])
	switch header {
	case SERVER_NEGOTIATE:
		err = handleNegotiate(req)
	case SERVER_EPHEMERAL:
		err = handleEphemeral(req)
	case SERVER_PROOF:
		err = handleProof(req)
	default:
		err = errors.New("Invalid packet type")
	}

	return
}

// Handle initial negotiation
func handleNegotiate(req *request) (err error) {
	var packet ServerNegotiate
	err = packet.UnmarshalBinary(req.message)
	if err != nil {
		return
	}

	return
}

// Handle SRP ephemeral exchange
func handleEphemeral(req *request) (err error) {
	var packet ServerEphemeral
	err = packet.UnmarshalBinary(req.message)
	if err != nil {
		return
	}

	return
}

// Handle SRP proof exchange
func handleProof(req *request) (err error) {
	var packet ServerProof
	err = packet.UnmarshalBinary(req.message)
	if err != nil {
		return
	}

	return
}
