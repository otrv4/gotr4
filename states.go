package gotra

const (
	stateStart = iota
	stateWaitingAuthR
	stateWaitingAuthI
	stateWaitingDakeDataMessage
	stateEncrypted
	stateFinished
)
