package gotra

type conversation struct {
}

func (c *conversation) Send(m ValidMessage, trace ...interface{}) ([]ValidMessage, error) {
	// TODO: sort out the flow here

	return nil, nil
}

func (c *conversation) Receive(m ValidMessage) (plain MessagePlaintext, toSend []ValidMessage, err error) {
	// TODO: sort out the flow here

	return nil, nil, nil
}
