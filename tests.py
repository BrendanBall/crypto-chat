import unittest
from unittest import TestCase
from unittest.mock import MagicMock
from queue import Queue
import client

class TestClient(TestCase):
	def test_protocol_init(self):
		client.process_message = MagicMock()
		q = Queue()
		q.put(["stdin", "bob: hi"])
		q.put(["stdin", "quit"])
		client.client(q, "alice")
		client.process_message.assert_called_with("bob: hi", "alice")

if __name__ == "__main__":
	unittest.main()
