/*
 *  Charon: A game authentication server
 *  Copyright (C) 2014-2016  Alex Mayfield <alexmax2742@gmail.com>
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
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"log"
	"net"
	"sync"
	"time"

	"github.com/AlexMax/charon/srp"
	"github.com/go-ini/ini"
)

// AuthApp contains all state for a single instance of the
// authentication server.
type AuthApp struct {
	config        *ini.File
	database      Database
	sessions      sessions
	sessionsMutex sync.Mutex
}

type sessions map[uint32]*srp.ServerSession

type request struct {
	address *net.UDPAddr
	message []byte
}

type response struct {
	address *net.UDPAddr
	message []byte
}

type routeFunc func(*request) (response, error)

// NewAuthApp creates a new instance of the auth server app.
func NewAuthApp(config *ini.File) (authApp *AuthApp, err error) {
	authApp = new(AuthApp)

	// Attach configuration
	authApp.config = config

	// Initialize database connection
	database, err := NewDatabase(config)
	if err != nil {
		return
	}
	authApp.database = *database

	// Initialize session store
	authApp.sessions = make(sessions)

	return
}

// ListenAndServe starts the auth server app.
func (self *AuthApp) ListenAndServe(addr string) (err error) {
	listenaddr, err := net.ResolveUDPAddr("udp", addr)
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
		go self.requestHandler(conn, &req)
	}
}

func (self *AuthApp) requestHandler(conn *net.UDPConn, req *request) {
	// Select callback function to route to.
	route, err := self.router(req)
	if err != nil {
		log.Printf("[DEBUG] %s", err.Error())
		return
	}

	// Route message to callback function.
	res, err := route(req)
	if err != nil {
		log.Printf("[DEBUG] %s", err.Error())
		return
	}

	// Respond to sender.
	_, err = conn.WriteToUDP(res.message, res.address)
	if err != nil {
		log.Printf("[DEBUG] %s", err.Error())
		return
	}
}

func (self *AuthApp) router(req *request) (route routeFunc, err error) {
	if len(req.message) < 4 {
		err = errors.New("Message is too small")
		return
	}

	// Route the message to the appropriate handler.
	header := binary.LittleEndian.Uint32(req.message[:4])
	switch header {
	case CharonServerNegotiate:
		route = self.handleNegotiate
	case CharonServerEphemeral:
		route = self.handleEphemeral
	case CharonServerProof:
		route = self.handleProof
	default:
		err = errors.New("Invalid packet type")
	}

	return
}

// Handle initial negotiation
func (self *AuthApp) handleNegotiate(req *request) (res response, err error) {
	var packet ServerNegotiate
	err = packet.UnmarshalBinary(req.message)
	if err != nil {
		return
	}

	// Ensure that the user exists.
	user, err := self.database.FindUser(packet.username)
	if err != nil {
		return
	}

	// Create a new random session ID
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

	// Create new SRP session
	srpo, err := srp.NewSRP("rfc5054.2048", sha256.New, nil)
	if err != nil {
		return
	}
	self.sessionsMutex.Lock()
	self.sessions[sessionID] = srpo.NewServerSession(
		[]byte(user.Username), user.Salt, user.Verifier)
	self.sessionsMutex.Unlock()
	go func() {
		// Time out session after a few seconds
		time.Sleep(time.Second * 5)
		self.sessionsMutex.Lock()
		delete(self.sessions, sessionID)
		self.sessionsMutex.Unlock()
	}()

	// Assemble response
	var resPacket AuthNegotiate
	resPacket.clientSession = packet.clientSession
	resPacket.session = sessionID
	resPacket.salt = user.Salt
	resPacket.username = user.Username
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
func (self *AuthApp) handleEphemeral(req *request) (res response, err error) {
	var packet ServerEphemeral
	err = packet.UnmarshalBinary(req.message)
	if err != nil {
		return
	}

	// Get session if it exists
	self.sessionsMutex.Lock()
	session, exists := self.sessions[packet.session]
	if exists == false {
		self.sessionsMutex.Unlock()
		err = errors.New("session does not exist")
		return
	}

	// Save client A and generate B
	_, err = session.ComputeKey(packet.ephemeral)
	if err != nil {
		self.sessionsMutex.Unlock()
		return
	}
	serverEphemeral := session.GetB()
	self.sessionsMutex.Unlock()

	// Assemble response
	var resPacket AuthEphemeral
	resPacket.session = packet.session
	resPacket.ephemeral = serverEphemeral
	message, err := resPacket.MarshalBinary()
	if err != nil {
		return
	}

	res.address = req.address
	res.message = message

	return
}

// Handle SRP proof exchange
func (self *AuthApp) handleProof(req *request) (res response, err error) {
	var packet ServerProof
	err = packet.UnmarshalBinary(req.message)
	if err != nil {
		return
	}

	// Get session if it exists
	self.sessionsMutex.Lock()
	session, exists := self.sessions[packet.session]
	if exists == false {
		self.sessionsMutex.Unlock()
		err = errors.New("session does not exist")
		return
	}

	if session.VerifyClientAuthenticator(packet.proof) == false {
		self.sessionsMutex.Unlock()
		err = errors.New("client authenticator is not valid")
		return
	}

	self.sessionsMutex.Unlock()
	return
}
