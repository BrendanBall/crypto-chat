import sys
from io import StringIO
import unittest
from unittest import TestCase
from unittest.mock import MagicMock
from queue import Queue
import client

class TestClient(TestCase):
	def setUp(self):
		client.router.close()
		client.router = MagicMock()

	def tearDown(self):
		# What's going on here is pretty bad, but it's because
		# of the horrible architecture in the actual code
		for state in client.states:
			state.clear()

		client.msg_store = []
		client.file_store = []
		client.nonces = {}
		client.keys = {}

	def test_protocol_init(self):
		"""
		If we don't have a connection with the client,
		start the protocol and save the message
		"""
		q = Queue()
		q.put(["stdin", "bob: hi"])
		q.put(["stdin", "quit"])
		client.client(q, "alice")
		
		client.router.send.assert_called_with(b'bob: alice')
		self.assertEqual(1, len(client.msg_store))

	def test_send_encrypted(self):
		"""
		If we DO have a connection, send the encrypted message
		"""
		client.keys = {"bob": "key"}
		client.active.append("bob")
		client.send_encrypted = MagicMock()
		q = Queue()
		q.put(["stdin", "bob: hi"])
		q.put(["stdin", "quit"])
		client.client(q, "alice")

		client.send_encrypted.assert_called_with("bob", "key", "hi")
		self.assertEqual(0, len(client.msg_store))

	def test_bad_nonce(self):
		saved_stdout = sys.stdout
		try:
			out = StringIO()
			sys.stdout = out
			client.keys["Auth"] = "K9gGyX8OAK8aH8Myj6djqSaXI8jbj6xPk69x2xhtbpA="
			# Right nonce is 2405145642
			client.nonces = {"bob": 1000000000}
			q = Queue()
			q.put(["socket", "(Auth) sUqtIZYScS9J8na4XP7t+Z6OhTkZMR8dAhRsQbCykfFA+23AsJpKNkAWqhP+kuRNIl8K9UwDrE0F1saECatMK7gMNfr6JZNcqn4kMNG7Vkop3wtL+tAYL+zS0LLsHpQfNAHUUwJWKbIvfVBlrBEleLPGPiS64El/srsbCO+2zSa7qxXaKB4oHjyyDRzbxcCHVmkreSDAPaz2vpTRcwHGhkUmzB2GxtzxiLbBA7WIuoNxz/rR"])
			q.put(["stdin", "quit"])
			client.client(q, "alice")

			output = out.getvalue().strip()

			client.router.send.assert_called_with(b'bob: /cancel')
			self.assertEqual("bob responded with wrong nonce\nCancelling connection with bob")
		except Exception as e:
			print(e)
		finally:
			sys.stdout = saved_stdout



if __name__ == "__main__":
	unittest.main()
