package gotra

func (c *conversation) getInstanceTag() uint32 {
	// TODO: implement correctly
	return 0x01020304
}

func (c *conversation) fixInstanceTag(other uint32) {
	// TODO: maybe we should do something here if there already is one?
	c.otherInstanceTag = other
}
