package gotra

import (
	"bytes"
	"io"
	"math/big"

	"github.com/coyim/gotrax"
	"github.com/otrv4/ed448"
)

type conversation struct {
	r                io.Reader
	longTerm         *gotrax.Keypair
	otherInstanceTag uint32

	currentClientProfile *gotrax.ClientProfile

	im  *identityMessage
	imp *identityMessagePrivate
	ar  *authRMessage
	arp *authRMessagePrivate
	ai  *authIMessage

	state convState

	ssid []byte

	ratchetId uint32
	ratchetJ  uint32
	ratchetK  uint32
	ratchetPN uint32

	rootKey           []byte
	sendingChainKey   []byte
	receivingChainKey []byte

	their_ecdh ed448.Point
	their_dh   *big.Int

	our_ecdh *gotrax.Keypair
	our_dh   *dhKeypair

	brace_key []byte

	shouldRatchet bool
}

// TODO: for all these functions, if we're currently in OTRv3 we should fall back to an otr3 conversation
// TODO: figure out how to decide how we should deal with offline etc. maybe a callback or something?
// TODO: fragmentation etc
// TODO: base64

// TODO: I don't remember how the traces are supposed to work. Figure that out later, I guess

func (c *conversation) Send(m MessagePlaintext, trace ...interface{}) ([]ValidMessage, error) {
	// TODO: sort out the flow here

	// - if we're in an encrypted state, just put it in a data message and send it
	// - if we're not encrypted, and encryption is optional, let's just send it
	//   - we will optionally add a whitespace tag here if policies say we should
	// - if we're in a finished state, this should probably result in an error or something

	return []ValidMessage{msgEncode(c.createDataMessage(m, []*tlv{}))}, nil
}

func msgEncode(msg []byte) []byte {
	return append(append(otrPrefix, b64encode(msg)...), '.')
}

func removeOTRMsgEnvelope(msg []byte) []byte {
	return msg[len(otrPrefix) : len(msg)-1]
}

func msgDecode(msg []byte) []byte {
	msg = removeOTRMsgEnvelope(msg)
	msg, _ = b64decode(msg)
	// TODO: don't ignore error here
	return msg
}

func isQueryMessage(m ValidMessage) bool {
	// TODO: make this work correctly
	return bytes.Equal(m, []byte("?OTRv4?"))
}

func isIdentityMessage(m ValidMessage) bool {
	// TODO: make this work correctly
	return bytes.HasPrefix(m, append(gotrax.AppendShort(nil, version), messageTypeIdentityMessage))
}

func isAuthRMessage(m ValidMessage) bool {
	// TODO: make this work correctly
	return bytes.HasPrefix(m, append(gotrax.AppendShort(nil, version), messageTypeAuthRMessage))
}

func isAuthIMessage(m ValidMessage) bool {
	// TODO: make this work correctly
	return bytes.HasPrefix(m, append(gotrax.AppendShort(nil, version), messageTypeAuthIMessage))
}

func isDataMessage(m ValidMessage) bool {
	// TODO: make this work correctly
	return bytes.HasPrefix(m, append(gotrax.AppendShort(nil, version), messageTypeDataMessage))
}

func (c *conversation) processQueryMessage(m ValidMessage) (plain MessagePlaintext, toSend []ValidMessage, err error) {
	// TODO:
	// if the message is 4 and we allow 4

	c.state = stateWaitingAuthR{}
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

	c.im = im

	c.state = stateWaitingAuthI{}

	return nil, []ValidMessage{c.createAuthRMessage()}, nil
}

func (c *conversation) processAuthRMessage(m ValidMessage) (plain MessagePlaintext, toSend []ValidMessage, err error) {
	// TODO:
	// - If the state is WAITING_AUTH_R:
	//   - If the receiver's instance tag in the message is not the sender's instance tag you are currently using, ignore the message.
	//   - Validate the Auth-R message.
	//   - If validation fails:
	//     - Ignore the message.
	//     - Stay in state WAITING_AUTH_R.
	//   - If validation succeeds:
	//     - Reply with an Auth-I message, as defined in Sending an Auth-I Message section.
	// - If the state is ENCRYPTED_MESSAGES:
	//   - If this Auth-R message is the same one you received earlier:
	//     - Retransmit your Auth-I Message.
	//   - Otherwise:
	//     - Ignore the message.
	// - If the state is not WAITING_AUTH_R:
	//   - Ignore this message.

	arm := &authRMessage{}
	_, ok := arm.deserialize(m)
	if !ok {
		// Ignore the message
		return nil, nil, nil
	}

	verr := arm.validate(c.getInstanceTag())
	if verr != nil {
		// Ignore the message
		return nil, nil, nil
	}

	c.ar = arm
	c.state = stateWaitingDakeDataMessage{}

	aim := c.createAuthIMessage()
	c.initializeRatchetR()

	return nil, []ValidMessage{aim}, nil
}

func (c *conversation) processAuthIMessage(m ValidMessage) (plain MessagePlaintext, toSend []ValidMessage, err error) {
	// TODO:
	// 	If the state is WAITING_AUTH_I:
	//    If the receiver's instance tag in the message is not the sender's instance tag you are currently using, ignore this message.
	//    Validate the Auth-I message.
	//      If validation fails:
	//        Ignore the message.
	//        Stay in state WAITING_AUTH_I.
	//      If validation succeeds:
	//        Transition to state ENCRYPTED_MESSAGES.
	//        Initialize the double ratcheting, as defined in the Interactive DAKE Overview section.
	//        Send a regular Data Message. If a plaintext message is waiting to be sent, this can be used. Otherwise an empty heartbeat message should be sent. This data message is called "DAKE Data Message".
	//        If there are stored Data Messages, remove them from storage - there is no way these messages can be valid for the current DAKE.
	// 	If the state is not WAITING_AUTH_I:
	//   - Ignore this message.

	aim := &authIMessage{}
	_, ok := aim.deserialize(m)
	if !ok {
		// Ignore the message
		return nil, nil, nil
	}

	verr := aim.validate(c.getInstanceTag())
	if verr != nil {
		// Ignore the message
		return nil, nil, nil
	}

	c.ai = aim

	// TODO: if result is error, don't ignore it
	c.initializeRatchetI()
	c.state = stateEncrypted{}

	// TODO: here we can send a message waiting to be sent OR a heartbeat

	return nil, []ValidMessage{c.createHeartbeatDataMessage()}, nil
}

func (c *conversation) processDataMessage(m ValidMessage) (plain MessagePlaintext, toSend []ValidMessage, err error) {
	// TODO: implement correctly

	dm := &dataMessage{}
	_, ok := dm.deserialize(m)
	if !ok {
		// Ignore the message
		return nil, nil, nil
	}

	verr := dm.validate(c.getInstanceTag())
	if verr != nil {
		// Ignore the message
		return nil, nil, nil
	}

	plain, toSend, err = c.receivedDataMessage(dm)
	// TODO: check if error here. but for now we can assume the ratchet is initialized
	if c.state.String() == "WAITING_DAKE_DATA_MESSAGE" {
		c.state = stateEncrypted{}
	}

	return
}

func (c *conversation) Receive(m ValidMessage) (plain MessagePlaintext, toSend []ValidMessage, err error) {
	// TODO: sort out the flow here

	if isQueryMessage(m) {
		plain, toSend, err = c.processQueryMessage(m)
	}

	dm := msgDecode(m)

	if isIdentityMessage(dm) {
		plain, toSend, err = c.processIdentityMessage(dm)
	}

	if isAuthRMessage(dm) {
		plain, toSend, err = c.processAuthRMessage(dm)
	}

	if isAuthIMessage(dm) {
		plain, toSend, err = c.processAuthIMessage(dm)
	}

	if isDataMessage(dm) {
		plain, toSend, err = c.processDataMessage(dm)
	}

	// - plaintext without tag
	// - plaintext with tag
	// - error message
	// - non-interactive auth message

	for ix, ts := range toSend {
		toSend[ix] = msgEncode(ts)
	}

	return
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
	// TODO: implement correctly

	// TODO: discard session keys

	dm := c.createDataMessage(nil, []*tlv{createDisconnectedTLV()})

	c.state = stateStart{}

	return []ValidMessage{msgEncode(dm)}, nil
}
