import unittest
from penelope import *

class TestPenelope(unittest.TestCase):

    def test_session_initialization(self):
        """Test initialization of the Session class."""
        session = Session(_socket=None, target='127.0.0.1', port=8080)
        self.assertIsNotNone(session)
        self.assertEqual(session.target, '127.0.0.1')
        self.assertEqual(session.port, 8080)

    def test_get_system_info(self):
        """Test the get_system_info method."""
        session = Session(_socket=None, target='127.0.0.1', port=8080)
        session.OS = 'Unix'
        # Вместо установки session.bin, мы замокаем метод exec
        session.exec = lambda cmd, **kwargs: "localhost\tLinux\tx86_64"
        # Устанавливаем значение _bin напрямую
        session._bin = {'uname': '/bin/uname'}
        result = session.get_system_info()
        self.assertTrue(result)
        self.assertEqual(session.hostname, 'localhost')
        self.assertEqual(session.system, 'Linux')
        self.assertEqual(session.arch, 'x86_64')

    def test_upload(self):
        """Test the upload method."""
        session = Session(_socket=None, target='127.0.0.1', port=8080)
        session.OS = 'Unix'
        # Вместо установки session.cwd, мы замокаем метод exec
        session.exec = lambda cmd, **kwargs: "0"
        # Устанавливаем значение _cwd напрямую
        session._cwd = '/tmp'
        result = session.upload(local_items=['file1.txt'], remote_path='/tmp')
        self.assertIsInstance(result, list)

if __name__ == '__main__':
    unittest.main()
