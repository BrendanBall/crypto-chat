# Crypto-Chat
A chat service written in python 3, which uses an authentication server to handle shared key encryption.

## Assumptions
We have made one key simplification to the protocol. In reality, each client would need to have a master key set up with the auth server. What we have done is set each client's key to a SHA256 hash of their name. In this way, we have 256 bit keys for each client which were ostensibly "set up before".

## Instructions
Run the router: 

`python3 router.py`

Run the auth server: 

`python3 auth.py host 8001`

Connect with as many clients as you like, with: 

`python3 client.py host 8001`

If your clients are on the same machine as the router, `host` is localhost.

The router will output all messages it sees. This is an analogy for an insecure link (i.e. the internet).

The first thing a client needs to do is register a name with
`/name name`
They can then send messages to other clients with
`client name: message`

To send a file to another client use:
`/file <client name> <file path>`

### Contributors
+ [Brendan Ball](https://github.com/brendanball)
+ [Andrew van Rooyen](https://github.com/wraithy)
