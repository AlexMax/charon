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
	"crypto/rand"
	"encoding/binary"
	"errors"
	"log"
	"net"
)

type request struct {
	address *net.UDPAddr
	message []byte
}

type response struct {
	address *net.UDPAddr
	message []byte
}

type routeFunc func(*request) (response, error)

// New creates a new instance of the Charon auth server.
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
		go requestHandler(&req)
	}
}

func requestHandler(req *request) {
	// Select callback function to route to.
	route, err := router(req)
	if err != nil {
		log.Printf("[DEBUG] %s", err.Error())
	}

	// Route message to callback function.
	res, err := route(req)
	if err != nil {
		log.Printf("[DEBUG] %s", err.Error())
	}

	// Respond to sender.
	conn, err := net.ListenUDP("udp", req.address)
	if err != nil {
		log.Printf("[DEBUG] %s", err.Error())
	}
	conn.WriteToUDP(res.message, res.address)
}

func router(req *request) (route routeFunc, err error) {
	if len(req.message) < 4 {
		err = errors.New("Message is too small")
		return
	}

	// Route the message to the appropriate handler.
	header := binary.LittleEndian.Uint32(req.message[:4])
	switch header {
	case CharonServerNegotiate:
		route = handleNegotiate
	case CharonServerEphemeral:
		route = handleEphemeral
	case CharonServerProof:
		route = handleProof
	default:
		err = errors.New("Invalid packet type")
	}

	return
}

// Handle initial negotiation
func handleNegotiate(req *request) (res response, err error) {
	var packet ServerNegotiate
	err = packet.UnmarshalBinary(req.message)
	if err != nil {
		return
	}

	// Create new session
	sessionBytes := make([]byte, 4)
	_, err = rand.Read(sessionBytes)
	if err != nil {
		return
	}
	var sessionID uint32
	sessionBuffer := bytes.NewBuffer(sessionBytes)
	err = binary.Read(sessionBuffer, binary.LittleEndian, &sessionID)
	if err != nil {
		return
	}

	// Assemble response
	var resPacket AuthNegotiate
	resPacket.clientSession = packet.clientSession
	resPacket.session = sessionID
	resPacket.username = packet.username
	resPacket.version = 2
	message, err := resPacket.MarshalBinary()
	if err != nil {
		return
	}

	res.address = req.address
	res.message = message

	return
}

// Handle SRP ephemeral exchange
func handleEphemeral(req *request) (res response, err error) {
	var packet ServerEphemeral
	err = packet.UnmarshalBinary(req.message)
	if err != nil {
		return
	}

	return
}

// Handle SRP proof exchange
func handleProof(req *request) (res response, err error) {
	var packet ServerProof
	err = packet.UnmarshalBinary(req.message)
	if err != nil {
		return
	}

	return
}
