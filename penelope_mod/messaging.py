import os
import struct
import threading
import queue

class Messenger:
    def __init__(self, socket):
        self.socket = socket
        
    def send(self, message):
        if isinstance(message, str):
            message = message.encode()
        self.socket.send(message)
        
    SHELL = 1
    RESIZE = 2
    EXEC = 3
    STREAM = 4

    STREAM_CODE = '!H'
    STREAM_BYTES = struct.calcsize(STREAM_CODE)

    LEN_CODE = 'H'
    _LEN_CODE = '!' + 'H'
    LEN_BYTES = struct.calcsize(LEN_CODE)

    TYPE_CODE = 'B'
    _TYPE_CODE = '!' + 'B'
    TYPE_BYTES = struct.calcsize(TYPE_CODE)

    HEADER_CODE = '!' + LEN_CODE

    def __init__(self, bufferclass):
        self.len = None
        self.input_buffer = bufferclass()
        self.length_buffer = bufferclass()
        self.message_buffer = bufferclass()

    def message(_type, _data):
        return struct.pack(Messenger.HEADER_CODE, len(_data) + Messenger.TYPE_BYTES, _type) + _data
    message = staticmethod(message)

    def feed(self, data):
        self.input_buffer.write(data)
        self.input_buffer.seek(0)

        while True:
            if not self.len:
                len_need = Messenger.LEN_BYTES - self.length_buffer.tell()
                data = self.input_buffer.read(len_need)
                self.length_buffer.write(data)
                if len(data) != len_need:
                    break

                self.len = struct.unpack(Messenger._LEN_CODE, self.length_buffer.getvalue())[0]
                self.length_buffer.seek(0)
                self.length_buffer.truncate()
            else:
                data_need = self.len - self.message_buffer.tell()
                data = self.input_buffer.read(data_need)
                self.message_buffer.write(data)
                if len(data) != data_need:
                    break

                self.message_buffer.seek(0)
                _type = struct.unpack(Messenger._TYPE_CODE, self.message_buffer.read(Messenger.TYPE_BYTES))[0]
                _message = self.message_buffer.read()

                self.len = None
                self.message_buffer.seek(0)
                self.message_buffer.truncate()
                yield _type, _message

        self.input_buffer.seek(0)
        self.input_buffer.truncate()

class Stream:
    def __init__(self, _id, _session=None):
        self.id = _id
        self._read, self._write = os.pipe()
        self.writebuf = None
        self.feed_thread = None
        self.session = _session

        if self.session is None:
            self.writefunc = lambda data: respond(self.id + data)
            cloexec(self._write)
            cloexec(self._read)
        else:
            self.writefunc = lambda data: self.session.send(Messenger.message(Messenger.STREAM, self.id + data))

    def __lshift__(self, data):
        if not self.writebuf:
            self.writebuf = queue.Queue()
        self.writebuf.put(data)
        if not self.feed_thread:
            self.feed_thread = threading.Thread(target=self.feed, name="feed stream -> " + repr(self.id))
            self.feed_thread.start()

    def feed(self):
        while True:
            data = self.writebuf.get()
            if not data:
                try:
                    os.close(self._write)
                except:
                    pass
                break
            try:
                os.write(self._write, data)
            except:
                break

    def fileno(self):
        return self._read

    def write(self, data):
        self.writefunc(data)

    def read(self, n):
        try:
            data = os.read(self._read, n)
        except:
            return "".encode()
        if not data:
            try:
                os.close(self._read)
            except:
                pass
        return data

# Utilities referenced indirectly by Stream in agent context
# They are expected to be provided in the agent runtime; here we just declare names for linters.
def respond(*args, **kwargs):
    pass

def cloexec(fd):
    try:
        import fcntl
        flags = fcntl.fcntl(fd, fcntl.F_GETFD)
        fcntl.fcntl(fd, fcntl.F_SETFD, flags | fcntl.FD_CLOEXEC)
    except Exception:
        pass