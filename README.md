# gotra - an implementation of OTRv4 in Golang

## Things to implement:

- Management of keys and fingerprints
- Communication with prekey server
- Management of client profiles, prekey profiles and prekey messages
- DAKEZ
- XZDH
- The basic ratcheting
- Sending and receiving of messages
- SMP 
- The other basic TLVs
- Fallback to OTRv3
- Fragmentation
- Policies


We should try to keep the API as similar as possible to OTRv3 - in fact, it
would be great if we could define an interface that covers both of them.
