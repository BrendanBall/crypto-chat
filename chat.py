import re
from Crypto import Random
from Crypto.Cipher import AES

help_str = """Send messages with "sender > receiver : message"
Other available commands are
  help   - show this message
  lskeys - show all shared keys"""

users = {}

# initialization vector
iv = b'g\x9e\xecI\x0f\x9b\x81*,\x94\xaa)\x96x$q'

def repl():
	print(help_str)
	while True:
		print("~ ", end="")
		s = input()
		if s == "help":
			print(help_str)
		elif s == "lskeys":
			for user in users.values():
				print(user.name)
				print("="*len(user.name))
				for name, key in user.keys.items():
					print("{0:<10}{1}".format(name, str(key)))
				print()
		elif not re.match("^\w+(\s?)>(\s?)\w+(\s?):(\s?).*", s):
			print("Invalid command")
		else:
			msg = s[s.find(":")+1:].strip()
			s = s.replace(" ", "")
			sep = s.find(">")
			sender = s[:sep]
			receiver = s[sep+1:s.find(":")]
			if sender in users:
				users[sender].send(receiver, msg)
			else:
				print("%s not found" % sender)

def broadcast(sender, receiver, msg):
	print("(Open) %s > %s : %s" % (sender, receiver, msg))
	if receiver in users:
		users[receiver].receive(sender, msg)

class User():
	def __init__(self, name):
		self.keys = {}
		self.name = name
		users[self.name] = self

	def add_key(self, name, key):
		self.keys[name] = key

	def remove_key(self, name, key):
		for n, k in self.keys.items():
			if n == name and k == key:
				del key[n]

	def send(self, user, msg):
		if user in self.keys:
			cipher = AES.new(self.keys[user], AES.MODE_CFB, iv)
			ciphertext = cipher.encrypt(str.encode(msg))
			broadcast(self.name, user, ciphertext)
		else:
			print("Error: %s has no shared key with %s" % (self.name, user))

	def receive(self, user, ciphertext):
		if user in self.keys:
			cipher = AES.new(self.keys[user], AES.MODE_CFB, iv)
			msg = cipher.decrypt(ciphertext)
			print("(%s) %s: %s" % (self.name, user, msg.decode("utf-8")))
		else:
			print("Error: %s has no shared key with %s" % (self.name, user))


if __name__ == "__main__":
	shared_key = b'sixteen byte key'
	alice = User("alice")
	bob = User("bob")
	alice.add_key("bob", shared_key)
	bob.add_key("alice", shared_key)
	try:
		repl()
	except (EOFError, KeyboardInterrupt):
		print("Interrupt")
