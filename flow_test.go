package gotra

import (
	"github.com/coyim/gotrax"
	. "gopkg.in/check.v1"
)

func (s *GotraSuite) Test_basicFlow_onlineWithQueryMessage(c *C) {
	// TODO: we'll have to add assertions of everything here later

	rand := gotrax.FixtureRand()

	alice := &conversation{r: rand, state: stateStart{}}
	bob := &conversation{r: rand, state: stateStart{}}

	c.Assert(alice.state, FitsTypeOf, stateStart{})
	c.Assert(bob.state, FitsTypeOf, stateStart{})

	aliceQuery := alice.QueryMessage()
	c.Assert(aliceQuery, Not(IsNil))

	bobPlain1, bobIdentity, bobErr1 := bob.Receive(aliceQuery)
	c.Assert(bobPlain1, IsNil)
	c.Assert(bobErr1, IsNil)
	c.Assert(bobIdentity, HasLen, 1)
	c.Assert(bob.state, FitsTypeOf, stateWaitingAuthR{})

	alicePlain1, aliceAuthR, aliceErr1 := alice.Receive(bobIdentity[0])
	c.Assert(alicePlain1, IsNil)
	c.Assert(aliceErr1, IsNil)
	c.Assert(aliceAuthR, HasLen, 1)
	c.Assert(alice.state, FitsTypeOf, stateWaitingAuthI{})

	bobPlain2, bobAuthI, bobErr2 := bob.Receive(aliceAuthR[0])
	c.Assert(bobPlain2, IsNil)
	c.Assert(bobErr2, IsNil)
	c.Assert(bobAuthI, HasLen, 1)
	c.Assert(bob.state, FitsTypeOf, stateWaitingDakeDataMessage{})

	alicePlain2, aliceDakeData, aliceErr2 := alice.Receive(bobAuthI[0])
	c.Assert(alicePlain2, IsNil)
	c.Assert(aliceErr2, IsNil)
	c.Assert(aliceDakeData, HasLen, 1)
	c.Assert(alice.state, FitsTypeOf, stateEncrypted{})

	bobPlain3, bobToSend1, bobErr3 := bob.Receive(aliceDakeData[0])
	c.Assert(bobPlain3, HasLen, 0)
	c.Assert(bobErr3, IsNil)
	c.Assert(bobToSend1, HasLen, 0)
	c.Assert(bob.state, FitsTypeOf, stateEncrypted{})

	// We are now ready to do stuff

	aliceToSend1, aliceErr3 := alice.Send(MessagePlaintext("hello there, Bob - how's life?"))
	c.Assert(aliceErr3, IsNil)
	c.Assert(aliceToSend1, HasLen, 1)

	aliceToSend2, aliceErr4 := alice.Send(MessagePlaintext("wanted to say something"))
	c.Assert(aliceErr4, IsNil)
	c.Assert(aliceToSend2, HasLen, 1)

	bobPlain4, bobToSend2, bobErr4 := bob.Receive(aliceToSend1[0])
	c.Assert(bobPlain4, DeepEquals, MessagePlaintext("hello there, Bob - how's life?"))
	c.Assert(bobErr4, IsNil)
	c.Assert(bobToSend2, HasLen, 0)

	bobPlain5, bobToSend3, bobErr5 := bob.Receive(aliceToSend2[0])
	c.Assert(bobPlain5, DeepEquals, MessagePlaintext("wanted to say something"))
	c.Assert(bobErr5, IsNil)
	c.Assert(bobToSend3, HasLen, 0)

	bobToSend4, bobErr4 := bob.Send(MessagePlaintext("oh yeah, what's that?"))
	c.Assert(bobErr4, IsNil)
	c.Assert(bobToSend4, HasLen, 1)

	alicePlain3, aliceToSend3, aliceErr5 := alice.Receive(bobToSend4[0])
	c.Assert(alicePlain3, DeepEquals, MessagePlaintext("oh yeah, what's that?"))
	c.Assert(aliceErr5, IsNil)
	c.Assert(aliceToSend3, HasLen, 0)

	aliceToSend4, aliceErr6 := alice.Send(MessagePlaintext("I wanted to say hello"))
	c.Assert(aliceErr6, IsNil)
	c.Assert(aliceToSend4, HasLen, 1)

	aliceToSend5, aliceErr7 := alice.End()
	c.Assert(aliceErr7, IsNil)
	c.Assert(aliceToSend5, HasLen, 1)
	c.Assert(alice.state, FitsTypeOf, stateStart{})

	bobPlain6, bobToSend5, bobErr6 := bob.Receive(aliceToSend4[0])
	c.Assert(bobPlain6, DeepEquals, MessagePlaintext("I wanted to say hello"))
	c.Assert(bobErr6, IsNil)
	c.Assert(bobToSend5, HasLen, 0)

	bobPlain7, bobToSend6, bobErr7 := bob.Receive(aliceToSend5[0])
	c.Assert(bobPlain7, HasLen, 0)
	c.Assert(bobErr7, IsNil)
	c.Assert(bobToSend6, HasLen, 0)
	c.Assert(bob.state, FitsTypeOf, stateFinished{})
}
