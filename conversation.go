package gotra

import (
	"bytes"
	"io"

	"github.com/coyim/gotrax"
)

type conversation struct {
	r                io.Reader
	longTerm         *gotrax.Keypair
	otherInstanceTag uint32
}

// TODO: for all these functions, if we're currently in OTRv3 we should fall back to an otr3 conversation
// TODO: figure out how to decide how we should deal with offline etc. maybe a callback or something?
// TODO: fragmentation etc
// TODO: base64

// TODO: I don't remember how the traces are supposed to work. Figure that out later, I guess

func (c *conversation) Send(m ValidMessage, trace ...interface{}) ([]ValidMessage, error) {
	// TODO: sort out the flow here

	// - if we're in an encrypted state, just put it in a data message and send it
	// - if we're not encrypted, and encryption is optional, let's just send it
	//   - we will optionally add a whitespace tag here if policies say we should
	// - if we're in a finished state, this should probably result in an error or something

	return nil, nil
}

func isQueryMessage(m ValidMessage) bool {
	// TODO: make this work correctly
	return bytes.Equal(m, []byte("?OTRv4?"))
}

func isIdentityMessage(m ValidMessage) bool {
	// TODO: make this work correctly
	return bytes.HasPrefix(m, append(gotrax.AppendShort(nil, version), messageTypeIdentityMessage))
}

func (c *conversation) processQueryMessage(m ValidMessage) (plain MessagePlaintext, toSend []ValidMessage, err error) {
	// TODO:
	// if the message is 4 and we allow 4
	//    transition to waitingAuthR
	//    return an identity message

	return nil, []ValidMessage{c.createIdentityMessage()}, nil
}

func (c *conversation) processIdentityMessage(m ValidMessage) (plain MessagePlaintext, toSend []ValidMessage, err error) {
	// TODO:
	// - if the state is START
	// - if the state is WAITING_AUTH_R
	// - if the state is WAITING_AUTH_I
	// - if the state is WAITING_DAKE_DATA_MESSAGE
	// - if the state is ENCRYPTED or FINISHED
	// - other

	im := &identityMessage{}
	_, ok := im.deserialize(m)
	if !ok {
		// Ignore the message
		return nil, nil, nil
	}

	verr := im.validate(c.getInstanceTag())
	if verr != nil {
		// Ignore the message
		return nil, nil, nil
	}

	c.fixInstanceTag(im.senderInstanceTag)

	// Transition to the WAITING_AUTH_I state.

	return nil, []ValidMessage{c.createAuthRMessage(im)}, nil
}

func (c *conversation) Receive(m ValidMessage) (plain MessagePlaintext, toSend []ValidMessage, err error) {
	// TODO: sort out the flow here

	if isQueryMessage(m) {
		return c.processQueryMessage(m)
	}

	if isIdentityMessage(m) {
		return c.processIdentityMessage(m)
	}

	// - plaintext without tag
	// - plaintext with tag
	// - error message
	// - identity message
	// - auth-r message
	// - auth-i message
	// - non-interactive auth message
	// - dake data message
	// - data message

	return nil, nil, nil
}

// QueryMessage returns a message that can be sent to request the start of an OTR session
// This function will return nil if the conversation is not in a valid state to start a conversation
func (c *conversation) QueryMessage() ValidMessage {
	// TODO: we should create this dynamically, with the approved supported versions
	return ValidMessage("?OTRv4?")
}

// End will end the conversation from this side, returning the messages to send to
// indicate the ending for the peer, or an error if something goes wrong
func (c *conversation) End() ([]ValidMessage, error) {
	return nil, nil
}
