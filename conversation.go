package gotra

type conversation struct {
}

// TODO: for all these functions, if we're currently in OTRv3 we should fall back to an otr3 conversation
// TODO: figure out how to decide how we should deal with offline etc. maybe a callback or something?
// TODO: fragmentation etc

func (c *conversation) Send(m ValidMessage, trace ...interface{}) ([]ValidMessage, error) {
	// TODO: sort out the flow here

	// - if we're in an encrypted state, just put it in a data message and send it
	// - if we're not encrypted, and encryption is optional, let's just send it
	//   - we will optionally add a whitespace tag here if policies say we should
	// - if we're in a finished state, this should probably result in an error or something

	return nil, nil
}

func (c *conversation) Receive(m ValidMessage) (plain MessagePlaintext, toSend []ValidMessage, err error) {
	// TODO: sort out the flow here

	// - plaintext without tag
	// - plaintext with tag
	// - query message
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
	return nil
}
