import unittest
import os
import socket
import sys
import tempfile
from unittest.mock import MagicMock, patch
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from penelope import Session, Core, Channel, Options
from penelope_mod.network import Interfaces
from penelope_mod.messaging import Messenger

class TestSession(unittest.TestCase):
    def setUp(self):
        self.mock_socket = MagicMock()
        self.session = Session(self.mock_socket, "127.0.0.1", 8080)
        
    def test_initialization(self):
        """Test basic session initialization"""
        self.assertEqual(self.session.target, "127.0.0.1")
        self.assertEqual(self.session.port, 8080)
        
    def test_upload_with_invalid_path(self):
        """Test upload method with invalid path"""
        self.session.OS = "Unix"
        # Вместо установки session.cwd, мы замокаем метод exec
        self.session.exec = MagicMock(return_value=None)
        # Устанавливаем значение _cwd напрямую
        self.session._cwd = "/tmp"
        
        result = self.session.upload(["nonexistent_file.txt"])
        self.assertEqual(result, [])

class TestCore(unittest.TestCase):
    def setUp(self):
        self.core = Core()
        
    def test_stop(self):
        """Test core stop functionality"""
        # Инициализируем необходимые атрибуты
        self.core.listeners = {}
        self.core.sessions = {}
        self.core.fileservers = {}
        # Создаем объект ControlQueue для атрибута control
        from penelope import ControlQueue
        self.core.control = ControlQueue()
        # Инициализируем атрибут started
        self.core.started = True
        # Вызываем метод stop и проверяем, что он не вызывает исключений
        try:
            self.core.stop()
            success = True
        except Exception:
            success = False
        self.assertTrue(success)

class TestChannel(unittest.TestCase):
    def setUp(self):
        self.channel = Channel()
        
    def test_channel_initialization(self):
        """Test channel initialization"""
        self.assertTrue(self.channel.active)
        self.assertTrue(hasattr(self.channel, 'control'))

class TestMessenger(unittest.TestCase):
    def setUp(self):
        self.mock_socket = MagicMock()
        self.messenger = Messenger(self.mock_socket)
        
    def test_send_message(self):
        """Test message sending"""
        self.messenger.socket = MagicMock()
        test_message = b"test message"
        self.messenger.send(test_message)
        self.messenger.socket.send.assert_called_with(test_message)

class TestInterfaces(unittest.TestCase):
    def test_interfaces_initialization(self):
        """Test interfaces initialization"""
        interfaces = Interfaces()
        self.assertIsNotNone(interfaces)
        self.assertTrue(hasattr(interfaces, 'interfaces'))

if __name__ == '__main__':
    unittest.main()
