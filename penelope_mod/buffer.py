class LineBuffer:
	def __init__(self, length):
		self.len = length
		self.lines = __import__('collections').deque(maxlen=self.len)

	def __lshift__(self, data):
		if isinstance(data, str):
			data = data.encode()
		if self.lines and not self.lines[-1].endswith(b'\n'):
			current_partial = self.lines.pop()
		else:
			current_partial = b''
		self.lines.extend((current_partial + data).split(b'\n'))
		return self

	def __bytes__(self):
		return b'\n'.join(self.lines)

