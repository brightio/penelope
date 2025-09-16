import os
import time
import threading
from datetime import timedelta

class PBar:
	pbars = []

	def __init__(self, end, caption="", barlen=None, queue=None, metric=None):
		self.end = end
		if type(self.end) is not int: self.end = len(self.end)
		self.active = True if self.end > 0 else False
		self.pos = 0
		self.percent = 0
		self.caption = caption
		self.bar = '#'
		self.barlen = barlen
		self.percent_prev = -1
		self.queue = queue
		self.metric = metric
		self.check_interval = 1
		if self.queue: self.trace_thread = threading.Thread(target=self.trace); self.trace_thread.start(); __class__.render_lock = threading.RLock()
		if self.metric: threading.Thread(target=self.watch_speed, daemon=True).start()
		else: self.metric = lambda x: f"{x:,}"
		__class__.pbars.append(self)
		print("\x1b[?25l", end='', flush=True)
		self.render()

	def __bool__(self):
		return self.active

	def __enter__(self):
		return self

	def __exit__(self, exc_type, exc_value, traceback):
		self.terminate()

	def trace(self):
		while True:
			data = self.queue.get()
			self.queue.task_done()
			if isinstance(data, int): self.update(data)
			elif data is None: break
			else: self.print(data)

	def watch_speed(self):
		self.pos_prev = 0
		self.elapsed = 0
		while self:
			time.sleep(self.check_interval)
			self.elapsed += self.check_interval
			self.speed = self.pos - self.pos_prev
			self.pos_prev = self.pos
			self.speed_avg = self.pos / self.elapsed
			if self.speed_avg: self.eta = int(self.end / self.speed_avg) - self.elapsed
			if self: self.render()

	def update(self, step=1):
		if not self: return False
		self.pos += step
		if self.pos >= self.end: self.pos = self.end
		self.percent = int(self.pos * 100 / self.end)
		if self.pos >= self.end: self.terminate()
		if self.percent > self.percent_prev: self.render()

	def render_one(self):
		self.percent_prev = self.percent
		left = f"{self.caption}["
		elapsed = "" if not hasattr(self, 'elapsed') else f" | Elapsed {timedelta(seconds=self.elapsed)}"
		speed = "" if not hasattr(self, 'speed') else f" | {self.metric(self.speed)}/s"
		eta = "" if not hasattr(self, 'eta') else f" | ETA {timedelta(seconds=self.eta)}"
		right = f"] {str(self.percent).rjust(3)}% ({self.metric(self.pos)}/{self.metric(self.end)}){speed}{elapsed}{eta}"
		bar_space = self.barlen or os.get_terminal_size().columns - len(left) - len(right)
		bars = int(self.percent * bar_space / 100) * self.bar
		print(f'\x1b[2K{left}{bars.ljust(bar_space, ".")}{right}\n', end='', flush=True)

	def render(self):
		if hasattr(__class__, 'render_lock'): __class__.render_lock.acquire()
		for pbar in __class__.pbars: pbar.render_one()
		print(f"\x1b[{len(__class__.pbars)}A", end='', flush=True)
		if hasattr(__class__, 'render_lock'): __class__.render_lock.release()

	def print(self, data):
		if hasattr(__class__, 'render_lock'): __class__.render_lock.acquire()
		print(f"\x1b[2K{data}", flush=True)
		self.render()
		if hasattr(__class__, 'render_lock'): __class__.render_lock.release()

	def terminate(self):
		if self.queue and threading.current_thread() != self.trace_thread: self.queue.join(); self.queue.put(None)
		if hasattr(__class__, 'render_lock'): __class__.render_lock.acquire()
		if not self: return
		self.active = False
		if hasattr(self, 'eta'): del self.eta
		if not any(__class__.pbars):
			self.render()
			print("\x1b[?25h" + '\n' * len(__class__.pbars), end='', flush=True)
			__class__.pbars.clear()
		if hasattr(__class__, 'render_lock'): __class__.render_lock.release()


class paint:
	_codes = {'RESET':0, 'BRIGHT':1, 'DIM':2, 'UNDERLINE':4, 'BLINK':5, 'NORMAL':22}
	_colors = {'black':0, 'red':1, 'green':2, 'yellow':3, 'blue':4, 'magenta':5, 'cyan':6, 'orange':136, 'white':231, 'grey':244}
	_escape = lambda codes: f"\001\x1b[{codes}m\002"

	def __init__(self, text=None, colors=None):
		self.text = str(text) if text is not None else None
		self.colors = colors or []

	def __str__(self):
		if self.colors:
			content = self.text + __class__._escape(__class__._codes['RESET']) if self.text is not None else ''
			return __class__._escape(';'.join(self.colors)) + content
		return self.text

	def __len__(self):
		return len(self.text)

	def __add__(self, text):
		return str(self) + str(text)

	def __mul__(self, num):
		return __class__(self.text * num, self.colors)

	def __getattr__(self, attr):
		self.colors.clear()
		for color in attr.split('_'):
			if color in __class__._codes:
				self.colors.append(str(__class__._codes[color]))
			else:
				prefix = "3" if color in __class__._colors else "4"
				self.colors.append(prefix + "8;5;" + str(__class__._colors[color.lower()]))
		return self


class Table:
	def __init__(self, list_of_lists=[], header=None, fillchar=" ", joinchar=" "):
		self.list_of_lists = list_of_lists

		self.joinchar = joinchar

		if type(fillchar) is str:
			self.fillchar = [fillchar]
		elif type(fillchar) is list:
			self.fillchar = fillchar
		self.data = []
		self.max_row_len = 0
		self.col_max_lens = []
		if header: self.header = header
		for row in self.list_of_lists:
			self += row

	@property
	def header(self):
		...

	@header.setter
	def header(self, header):
		self.add_row(header, header=True)

	def __str__(self):
		self.fill()
		return "\n".join([self.joinchar.join(row) for row in self.data])

	def __len__(self):
		return len(self.data)

	def add_row(self, row, header=False):
		row_len = len(row)
		if row_len > self.max_row_len:
			self.max_row_len = row_len

		cur_col_len = len(self.col_max_lens)
		for _ in range(row_len - cur_col_len):
			self.col_max_lens.append(0)

		for _ in range(cur_col_len - row_len):
			row.append("")

		new_row = []
		for index, element in enumerate(row):
			if not isinstance(element, (str, paint)):
				element = str(element)
			elem_length = len(element)
			new_row.append(element)
			if elem_length > self.col_max_lens[index]:
				self.col_max_lens[index] = elem_length

		if header:
			self.data.insert(0, new_row)
		else:
			self.data.append(new_row)

	def __iadd__(self, row):
		self.add_row(row)
		return self

	def fill(self):
		for row in self.data:
			for index, element in enumerate(row):
				fillchar = ' '
				if index in [*self.fillchar][1:]:
					fillchar = self.fillchar[0]
				row[index] = element + fillchar * (self.col_max_lens[index] - len(element))


class Size:
	units = ("", "K", "M", "G", "T", "P", "E", "Z", "Y")
	def __init__(self, _bytes):
		self.bytes = _bytes

	def __str__(self):
		index = 0
		new_size = self.bytes
		while new_size >= 1024 and index < len(__class__.units) - 1:
			new_size /= 1024
			index += 1
		return f"{new_size:.1f} {__class__.units[index]}Bytes"

	@classmethod
	def from_str(cls, string):
		import logging
		logger = logging.getLogger("penelope")
		if string.isnumeric():
			_bytes = int(string)
		else:
			try:
				num, unit = int(string[:-1]), string[-1]
				_bytes = num * 1024 ** __class__.units.index(unit)
			except:
				logger.error("Invalid size specified")
				return
		return cls(_bytes)


