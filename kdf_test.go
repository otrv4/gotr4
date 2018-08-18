package gotra

import . "gopkg.in/check.v1"

func (s *GotraSuite) Test_kdfPrekeyServer_generatesCorrectValues(c *C) {
	v := kdfPrekeyServer(usageBraceKey, 3, []byte("one"), []byte("two"))
	c.Assert(v, DeepEquals, []byte{
		0xce, 0x5b, 0x44,
	})

	v2 := kdfPrekeyServer(usageFingerprint, 3, []byte("one"), []byte("two"))
	c.Assert(v2, DeepEquals, []byte{
		0xc8, 0x05, 0x30,
	})
}

func (s *GotraSuite) Test_kdfxPrekeyServer_generatesCorrectValues(c *C) {
	v := make([]byte, 3)
	kdfxPrekeyServer(usageBraceKey, v, []byte("one"), []byte("two"))
	c.Assert(v, DeepEquals, []byte{
		0xce, 0x5b, 0x44,
	})

	kdfxPrekeyServer(usageFingerprint, v, []byte("one"), []byte("two"))
	c.Assert(v, DeepEquals, []byte{
		0xc8, 0x05, 0x30,
	})
}

func (s *GotraSuite) Test_kdf_generatesCorrectValues(c *C) {
	v := kdf(usageBraceKey, 3, []byte("one"), []byte("two"))
	c.Assert(v, DeepEquals, []byte{
		0x7e, 0xa6, 0x9e,
	})

	v2 := kdf(usageFingerprint, 3, []byte("one"), []byte("two"))
	c.Assert(v2, DeepEquals, []byte{
		0x89, 0x6b, 0x14,
	})
}

func (s *GotraSuite) Test_kdfx_generatesCorrectValues(c *C) {
	v := make([]byte, 3)
	kdfx(usageBraceKey, v, []byte("one"), []byte("two"))
	c.Assert(v, DeepEquals, []byte{
		0x7e, 0xa6, 0x9e,
	})

	kdfx(usageFingerprint, v, []byte("one"), []byte("two"))
	c.Assert(v, DeepEquals, []byte{
		0x89, 0x6b, 0x14,
	})
}
