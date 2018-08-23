package gotra

type convState interface {
	next()
	String() string
}

type stateStart struct{}
type stateWaitingAuthR struct{}
type stateWaitingAuthI struct{}
type stateWaitingDakeDataMessage struct{}
type stateEncrypted struct{}
type stateFinished struct{}

func (stateStart) next()                  {}
func (stateWaitingAuthR) next()           {}
func (stateWaitingAuthI) next()           {}
func (stateWaitingDakeDataMessage) next() {}
func (stateEncrypted) next()              {}
func (stateFinished) next()               {}

func (stateStart) String() string                  { return "START" }
func (stateWaitingAuthR) String() string           { return "WAITING_AUTH_R" }
func (stateWaitingAuthI) String() string           { return "WAITING_AUTH_I" }
func (stateWaitingDakeDataMessage) String() string { return "WAITING_DAKE_DATA_MESSAGE" }
func (stateEncrypted) String() string              { return "ENCRYPTED" }
func (stateFinished) String() string               { return "FINISHED" }
