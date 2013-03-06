#! /usr/bin/env python
import socket, threading, time, errno, tkFont, os, json, binascii, ast, codecs, traceback
from Tkinter import *
import Queue
from ttk import Frame, Entry, Button, Label, Style, Checkbutton, Radiobutton, Combobox

class SocketThread(threading.Thread):
	
	def __init__(self, is_udp=False, addr=None):
		threading.Thread.__init__(self)
		self.is_udp = is_udp
		self._is_closed = True
		self._shedule_disconnect = False
		self._socket = None
		
		self._in_buffer = str()
		self._out_buffer = str()
		
		self.on_exception = None
		self.on_connected = None
		self.on_disconnected = None
		self.on_recv = None
		
		if addr:
			self.connect(addr)
	
	def connect(self, addr):
		"Connect to specified address"
		if self._is_closed:
			self.addr = addr
			try:
				if self.is_udp:
					self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
				else:
					self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				self._socket.connect(self.addr)
				self._socket.setblocking(0)
				self._is_closed = False
			except Exception, e:
				self._is_closed = True
				self._handle_exception(e)
			else:
				self.start()
	
	def disconnect(self):
		if not self._is_closed:
			self._shedule_disconnect = True
	
	def is_closed(self):
		return self._is_closed
	
	def send(self, data):
		self._out_buffer += data
	
	def _empty_out_buffer(self, size):
		if size is None or size < 0:
			self._out_buffer = str()
		elif size > 0:
			self._out_buffer = self._out_buffer[size:]
	
	def _empty_in_buffer(self, size=None):
		if size is None or size < 0:
			self._in_buffer = str()
		elif size > 0:
			self._in_buffer = self._in_buffer[size:]
	
	def _process_socket(self):
		"Process recv and send"
		try:
			data = self._socket.recv(4096)
			if len(data) == 0:
				# remote host disconnected
				self.disconnect()
			else:
				self._in_buffer += data
		except socket.error, e:
			if e.errno == errno.EBADF or e.errno == 10054:
				# remote host disconnected
				self.disconnect()
			elif e.errno == 11 or e.errno == 10035:
				pass
			else:
				raise
		self._process_recv()
		if len(self._out_buffer):
			size = self._socket.send(self._out_buffer)
			self._empty_out_buffer(size)
	
	def _process_recv(self):
		"Process input buffer change event"
		if len(self._in_buffer):
			if self.on_recv:
				size = None
				try:
					size = self.on_recv(self, self._in_buffer)
				except Exception, e:
					self._handle_exception(e)
				self._empty_in_buffer(size)
			else:
				self._empty_in_buffer()
	
	def _handle_exception(self, exc):
		if self.on_exception:
			self.on_exception(self, exc)
	
	def run(self):
		if not self._is_closed:
			if self.on_connected:
				try:
					self.on_connected(self)
				except Exception, e:
					self._handle_exception(e)
			while True:
				self._process_socket()
				if self._shedule_disconnect:
					try:
						self._socket.shutdown(socket.SHUT_RDWR)
					except:
						pass
					self._socket.close()
					self._is_closed = True
					if self.on_disconnected:
						try:
							self.on_disconnected(self)
						except Exception, e:
							self._handle_exception(e)
					break
				time.sleep(0.001)

class AsyncSender(Frame):
	
	def __init__(self, parent):
		Frame.__init__(self, parent)
		self.parent = parent
		
		self.log_queue = Queue.Queue()
		self.do_queue = Queue.Queue()
		
		self.async_socket = None
		self.parent.protocol("WM_DELETE_WINDOW", self.window_closed)
		
		self.host_var = StringVar()
		self.port_var = IntVar()
		self.is_udp_var = IntVar()
		self.send_as_var = IntVar()
		self.show_as_var = IntVar()
		self.log_font_size_var = StringVar()
		self.log_word_wrap_var = IntVar()
		self.is_add_cr = IntVar()
		self.is_add_lf = IntVar()
		self.is_auto_send = IntVar()
		self.auto_send_interval = StringVar()
		self.send_var = StringVar()
		self.encodings = ("ASCII", "CP1251", "CP866", "KOI8-R", "UTF-8", "UTF-16LE", "UTF-16BE")
		
		self.max_send_history = 100
		self.send_history = []
		
		self.user_dir = os.environ.get("USERPROFILE") or os.environ.get("HOME") or os.path.abspath(".")
		self.settings_file = os.path.join(self.user_dir, ".async_sender.settings")
		self.log_file = os.path.join(self.user_dir, ".async_sender.log")
		
		if not self.load_settings():
			self.set_default_settings()
		
		self.is_connected = False
		
		self.init_ui()
		
		self.after(20, self.check_log_queue)
		self.after(20, self.check_do_queue)
		
		self.parent.report_callback_exception = self.exception_callback
		
		self.apply_settings()
		
		self.log("Started")
	
	def exception_callback(self, exc_type, exc, tb):
		self.log("Callback exception traceback:\n%s" % "".join(traceback.format_exception(exc_type, exc, tb)) )
	
	def load_settings(self):
		try:
			self.settings = json.load(open(self.settings_file))
			def_sett = self.get_default_settings()
			for key in def_sett:
				if key not in self.settings:
					self.settings[key] = def_sett[key]
		except Exception, e:
			print "Exception %s in load_settings: %s" % (type(e), e)
			return False
		return True
	
	def save_settings(self):
		# collect settings first
		self.settings["send_as"] = self.send_as_var.get()
		self.settings["show_as"] = self.show_as_var.get()
		self.settings["add_cr"] = self.is_add_cr.get()
		self.settings["add_lf"] = self.is_add_lf.get()
		self.settings["host"] = self.host_var.get()
		self.settings["port"] = self.port_var.get()
		self.settings["is_udp"] = self.is_udp_var.get()
		self.settings["log_font_size"] = int(self.log_font_size_var.get())
		self.settings["log_word_wrap"] = self.log_word_wrap_var.get()
		self.settings["in_encoding"] = self.in_encoding_cb.current()
		self.settings["out_encoding"] = self.out_encoding_cb.current()
		self.settings["auto_send_interval"] = self.auto_send_interval.get()
		self.settings["send_history"] = self.send_history
		self.settings["window_geometry"] = self.parent.geometry()
		# store
		try:
			json.dump(self.settings, open(self.settings_file, "wb"), sort_keys=True, indent=2, separators=(',', ': '))
		except Exception, e:
			print "Exception %s in save_settings: %s" % (type(e), e)
			pass
	
	def get_default_settings(self):
		return {
			"send_as": 0,
			"show_as": 1,
			"add_cr": 1,
			"add_lf": 1,
			"host": "",
			"port": 0,
			"is_udp": 0,
			"log_font_size": 8,
			"log_word_wrap": 0,
			"in_encoding": 4,
			"out_encoding": 4,
			"auto_send_interval": 5,
			"send_history": [],
			"window_geometry": "1000x600+20+20",
		}
	
	def set_default_settings(self):
		self.settings = self.get_default_settings()
	
	def apply_settings(self):
		self.send_as_var.set(self.settings["send_as"])
		self.apply_send_as()
		self.show_as_var.set(self.settings["show_as"])
		self.is_add_cr.set(self.settings["add_cr"])
		self.is_add_lf.set(self.settings["add_lf"])
		self.host_var.set(self.settings["host"])
		self.port_var.set(self.settings["port"])
		self.is_udp_var.set(self.settings["is_udp"])
		self.log_font_size_var.set(str(self.settings["log_font_size"]))
		self.apply_log_font_size()
		self.log_word_wrap_var.set(self.settings["log_word_wrap"])
		self.apply_log_word_wrap()
		self.in_encoding_cb.current(self.settings["in_encoding"])
		self.out_encoding_cb.current(self.settings["out_encoding"])
		self.auto_send_interval.set(self.settings["auto_send_interval"])
		self.send_history = self.settings["send_history"]
		self.send_history_pos = len(self.send_history)
		self.parent.geometry(self.settings["window_geometry"])
	
	def save_log(self):
		try:
			f = None
			if os.path.exists(self.log_file):
				f = codecs.open(self.log_file, "a", "utf-8")
			else:
				f = codecs.open(self.log_file, "wb", "utf-8")
			f.write(unicode(self.out_text.get(1.0,END).rstrip()) + "\n")
		except Exception, e:
			print "Exception %s in save_log: %s" % (type(e), e)
		finally:
			if f: f.close()
	
	def window_closed(self):
		self.do_disconnect()
		self.save_settings()
		self.log("Terminated")
		self.save_log()
		self.parent.destroy()
	
	def entry_ctrl_a_bind(self, e):
		e.widget.select_range(0, END)
		return "break"
	
	def text_ctrl_a_bind(self, e):
		e.widget.tag_add("sel","1.0","end")
		return "break"
	
	def send_history_up(self, e):
		if self.send_history_pos:
			self.send_history_pos -= 1
			self.send_var.set(self.send_history[self.send_history_pos])
			self.send_e.select_range(0, 0)
	
	def send_history_down(self, e):
		if self.send_history_pos < len(self.send_history) - 1:
			self.send_history_pos += 1
			self.send_var.set(self.send_history[self.send_history_pos])
			self.send_e.select_range(0, 0)
	
	def push_send_history(self, value):
		if len(self.send_history):
			if value == self.send_history[-1]:
				return
		if len(self.send_history) > self.max_send_history:
			self.send_history = self.send_history[1:]
		self.send_history.append(value)
		self.send_history_pos = len(self.send_history) - 1
	
	def init_ui(self):
		self.parent.title("Async sender/receiver")
		self.style = Style()
		self.style.theme_use("default")
		self.pack(fill=BOTH, expand=1)
		
		self.font = tkFont.Font(family="Courier New", size=8)
		
		# upper-left block with connection controls
		conn_control_frame = Frame(self)
		host_lab = Label(conn_control_frame, text="Host:")
		host_lab.grid(sticky=W, padx=2, pady=2)
		self.host_e = Entry(conn_control_frame, width=30, textvariable=self.host_var)
		self.host_e.grid(row=0, column=1, columnspan=3, padx=2, pady=2, sticky=W)
		self.host_e.bind("<Control-a>", self.entry_ctrl_a_bind)
		port_lab = Label(conn_control_frame, text="Port:")
		port_lab.grid(row=1, column=0, padx=2, pady=2)
		self.port_e = Entry(conn_control_frame, width=6, textvariable=self.port_var)
		self.port_e.grid(row=1, column=1, padx=2, pady=2, sticky=W)
		self.port_e.bind("<Control-a>", self.entry_ctrl_a_bind)
		self.is_tcp_rb = Radiobutton(conn_control_frame, text="TCP", variable=self.is_udp_var, value=0)
		self.is_tcp_rb.grid(row=1, column=2, sticky=W, padx=2, pady=2)
		self.is_udp_rb = Radiobutton(conn_control_frame, text="UDP", variable=self.is_udp_var, value=1)
		self.is_udp_rb.grid(row=1, column=3, sticky=W, padx=2, pady=2)
		self.connect_btn = Button(conn_control_frame, text="Connect", command=self.connect_click)
		self.connect_btn.grid(row=0, column=4, rowspan=2, padx=2, pady=2, sticky=N+S+W+E)
		conn_control_frame.grid(sticky=W, padx=2, pady=2)
		
		# log textarea with scrollbars
		self.out_text = Text(self, wrap=NONE, font=self.font)
		self.out_text.grid(row=1, column=0, sticky=N+S+E+W)
		self.out_text.bind("<Control-a>", self.text_ctrl_a_bind)
		out_vsb = Scrollbar(self, orient=VERTICAL, command=self.out_text.yview)
		out_vsb.grid(row=1, column=1, sticky=N+S)
		self.out_text["yscrollcommand"] = out_vsb.set
		out_hsb = Scrollbar(self, orient=HORIZONTAL, command=self.out_text.xview)
		out_hsb.grid(row=2, column=0, sticky=E+W)
		self.out_text["xscrollcommand"] = out_hsb.set
		
		# bottom-left send data entry
		self.send_e = Entry(self, textvariable=self.send_var)
		self.send_e.grid(row=3, column=0, columnspan=2, sticky=E+W, padx=2, pady=2)
		self.send_e.bind("<Return>", self.send_e_return)
		self.send_e.bind("<Control-a>", self.entry_ctrl_a_bind)
		self.send_e.bind("<Up>", self.send_history_up)
		self.send_e.bind("<Down>", self.send_history_down)
		self.send_btn = Button(self, text="Send", command=self.send_click)
		self.send_btn.grid(row=3, column=2, sticky=E+W)
		
		# right panel with options
		opts_frame = Frame(self)
		Label(opts_frame, text="Log:").pack(anchor=W, fill=X, expand=1, padx=2, pady=8)
		Checkbutton(opts_frame, text="Word wrap", variable=self.log_word_wrap_var, command=self.apply_log_word_wrap).pack(anchor=W, fill=X, expand=1, padx=2, pady=2)
		Label(opts_frame, text="Font:").pack(anchor=W, padx=2, pady=2)
		self.log_font_size = Spinbox(opts_frame, values=tuple(xrange(8, 25)), command=self.apply_log_font_size, width=5)
		self.log_font_size["textvariable"] = self.log_font_size_var
		self.log_font_size["state"] = "readonly"
		self.log_font_size.pack(anchor=W, expand=1, padx=2, pady=2)
		Label(opts_frame, text="You send as:").pack(anchor=W, fill=X, expand=1, padx=2, pady=8)
		Radiobutton(opts_frame, text="TEXT", variable=self.send_as_var, value=0, command=self.apply_send_as).pack(fill=X, expand=1, padx=2, pady=2)
		self.add_cr_cb = Checkbutton(opts_frame, text="Add 0x0D (\\r)", variable=self.is_add_cr)
		self.add_cr_cb.pack(fill=X, expand=1, padx=2, pady=2)
		self.add_lf_cb = Checkbutton(opts_frame, text="Add 0x0A (\\n)", variable=self.is_add_lf)
		self.add_lf_cb.pack(fill=X, expand=1, padx=2, pady=2)
		Radiobutton(opts_frame, text="REPR", variable=self.send_as_var, value=1, command=self.apply_send_as).pack(fill=X, expand=1, padx=2, pady=2)
		Radiobutton(opts_frame, text="HEX", variable=self.send_as_var, value=2, command=self.apply_send_as).pack(fill=X, expand=1, padx=2, pady=2)
		Label(opts_frame, text="Incoming show as:").pack(fill=X, expand=1, padx=2, pady=8)
		Radiobutton(opts_frame, text="TEXT", variable=self.show_as_var, value=0).pack(fill=X, expand=1, padx=2, pady=2)
		Radiobutton(opts_frame, text="REPR", variable=self.show_as_var, value=1).pack(fill=X, expand=1, padx=2, pady=2)
		Radiobutton(opts_frame, text="HEX", variable=self.show_as_var, value=2).pack(fill=X, expand=1, padx=2, pady=2)
		Label(opts_frame, text="Incoming encoding:").pack(fill=X, expand=1, padx=2, pady=8)
		self.in_encoding_cb = Combobox(opts_frame, state='readonly', values=self.encodings, width=10)
		self.in_encoding_cb.current(0)
		self.in_encoding_cb.pack(fill=X, expand=1, padx=2, pady=2)
		Label(opts_frame, text="Outgoing encoding:").pack(fill=X, expand=1, padx=2, pady=8)
		self.out_encoding_cb = Combobox(opts_frame, state='readonly', values=self.encodings, width=10)
		self.out_encoding_cb.current(0)
		self.out_encoding_cb.pack(fill=X, expand=1, padx=2, pady=2)
		
		self.auto_send_cb = Checkbutton(opts_frame, text="Auto send every:", variable=self.is_auto_send, command=self.is_auto_send_changed)
		self.auto_send_cb.pack(fill=X, expand=1, padx=2, pady=8)
		self.auto_send_cb = Spinbox(opts_frame, values=tuple(xrange(1, 61)), width=3)
		self.auto_send_cb["textvariable"] = self.auto_send_interval
		self.auto_send_cb["state"] = "readonly"
		self.auto_send_cb.pack(anchor=W, expand=1, padx=2, pady=2)
		Button(opts_frame, text="About/Info", command=self.show_about).pack(side=BOTTOM, expand=1, fill=X, padx=2, pady=10)
		opts_frame.grid(row=0, column=2, rowspan=3)
		
		self.columnconfigure(0, weight=1)
		self.rowconfigure(1, weight=1)
		
		self.parent.bind("<Control-l>", lambda e: self.send_e.focus_set())
		
		self.upd_interface(self.is_connected)
	
	def apply_log_font_size(self):
		size = int(self.log_font_size_var.get())
		if self.font["size"] != size:
			self.font["size"] = size
	
	def show_about(self):
		tl = Toplevel(self.parent)
		tl.title("About and Info")
		tl.geometry("420x230")
		Label(tl, text="Asynchronous sender and receiver\nWritten by HasK (aka kial in Gurtam)").pack(pady=10)
		Label(tl, text="Your settings and log:\n%s\n%s" % (self.settings_file, self.log_file)).pack(pady=4)
		Label(tl, text="All issues please send to xhaskx@gmail.com or kial@gurtam.com").pack(pady=10)
		Label(tl, text="Have a good day!").pack(pady=10)
		Button(tl, text="Close", command=lambda: tl.destroy()).pack(side=BOTTOM, pady=10)
		tl.focus_set()
		tl.grab_set()
		tl.transient(self.parent)
		tl.wait_window(tl)
	
	def apply_log_word_wrap(self):
		self.out_text["wrap"] = WORD if self.log_word_wrap_var.get() else NONE
	
	def apply_send_as(self):
		self.add_lf_cb["state"] = self.add_cr_cb["state"] = DISABLED if self.send_as_var.get() else "normal"
	
	def is_auto_send_changed(self):
		if self.is_auto_send.get():
			self.after(int(self.auto_send_interval.get()) * 1000, self.auto_send)
	
	def auto_send(self):
		if self.is_auto_send.get():
			if self.is_connected and self.send_var.get():
				self.send_click()
			self.after(int(self.auto_send_interval.get()) * 1000, self.auto_send)
	
	def send_e_return(self, evt):
		self.send_click()
	
	def do_upd_interface(self, state):
		if isinstance(state, bool):
			if state:
				state = "normal"
			else:
				state = DISABLED
		self.send_btn["state"] = self.send_e["state"] = state
		self.host_e["state"] = self.port_e["state"] = self.is_udp_rb["state"] = self.is_tcp_rb["state"] = DISABLED if state == "normal" else "normal"
		if state == DISABLED:
			self.connect_btn["text"] = "Connect"
		else:
			self.connect_btn["text"] = "Disconnect"
	
	def upd_interface(self, state):
		# self.do_upd_interface(state)
		self.do_queue.put((self.do_upd_interface, state))
	
	def hex2data(self, hex_str):
		ready_hex = hex_str.replace(" ", "")
		try:
			data = binascii.unhexlify(ready_hex)
		except:
			return
		else:
			return data
	
	def make_log_data(self, data, force_type=None):
		show_type = force_type or self.show_as_var.get()
		if show_type == 0:
			log_data = u"TEXT: %s" % data
		elif show_type == 1:
			rd = repr(data)
			if rd[0] == "u":
				rd = rd[1:]
			log_data = u"REPR: %s" % rd[1:-1]
		elif show_type == 2:
			log_data = " HEX: %s" % binascii.hexlify(data).upper()
		else:
			self.log("Something wrong with 'show_as' variable. Please swith it (see right side)")
			return
		return log_data
	
	def process_send_encoding(self, data):
		return data.encode(self.encodings[self.out_encoding_cb.current()])
	
	def process_incoming_encoding(self, data):
		return data.decode(self.encodings[self.in_encoding_cb.current()])
	
	def send_click(self):
		try:
			send_type = self.send_as_var.get()
			log_data = None
			
			data_src = unicode(self.send_var.get())
			data = None
			
			if send_type == 0:
				# TEXT
				data = self.process_send_encoding(data_src)
				if self.is_add_cr.get():
					data += "\r"
				if self.is_add_lf.get():
					data += "\n"
				if data:
					log_data = "TEXT: %s" % data_src
			elif send_type == 1:
				# REPR
				data = self.process_send_encoding(ast.literal_eval("u'%s'" % data_src))
				if data:
					log_data = "REPR: %s" % data_src
			elif send_type == 2:
				# HEX
				data = self.hex2data(data_src)
				if data:
					log_data = " HEX: %s" % data_src
			else:
				data = None
				self.log("Something wrong with 'send_as' variable. Please swith it (see right side)")
			
			if data and log_data:
				self.async_socket.send(data)
				self.log("<<    (%5d): %s" % (len(data), log_data))
				self.send_e.select_range(0, END)
				self.push_send_history(data_src)
		except (UnicodeEncodeError, UnicodeDecodeError), e:
			self.log("Encoding error: %s. Try to select other encoding (see right side)" % e)
		except Exception, e:
			self.log("Send exception %s: %s" % (type(e), e))
		self.send_e.focus_set()
	
	def check_log_queue(self):
		try:
			res = self.log_queue.get(block=False)
		except Queue.Empty:
			pass
		else:
			self.out_text.insert(END, res)
			self.out_text.see(END)
		self.after(20, self.check_log_queue)
	
	def check_do_queue(self):
		try:
			res = self.do_queue.get(block=False)
		except Queue.Empty:
			pass
		else:
			func = res[0]
			args = res[1:]
			func(*args)
		self.after(20, self.check_do_queue)
	
	def log(self, msg):
		res = "%s: %s\n" % (time.strftime("%Y/%m/%d %H:%M:%S"), msg)
		self.log_queue.put(res)
	
	def on_disconnected(self, sock):
		self.log("Disconnected from %s:%s" % sock.addr)
		self.is_connected = False
		self.upd_interface(self.is_connected)
	
	def on_recv(self, sock, data):
		data_src = data
		try:
			if self.show_as_var.get() != 2:
				data = unicode(self.process_incoming_encoding(data))
			else:
				data = data_src
			self.log(u"    >>(%5d): %s" % (len(data), self.make_log_data(data)))
		except UnicodeDecodeError, e:
			self.log("Incoming data decoding error (displayed as HEX). Try to select other encoding (see right side)")
			self.log(u"    >>(%5d): %s" % (len(data), self.make_log_data(data_src, force_type=2)))
	
	def on_connected(self, sock):
		self.log("Connected to %s:%s" % sock.addr)
	
	def on_exception(self, sock, exc):
		if type(exc) == socket.gaierror:
			self.log("Socket exception: %s" % exc)
		else:
			raise exc
		print self.is_connected
		if self.is_connected:
			if self.async_socket.is_closed() == self.is_connected:
				self.is_connected = False
				self.upd_interface(self.is_connected)
	
	def do_disconnect(self):
		if self.async_socket and not self.async_socket.is_closed():
			self.async_socket.disconnect()
			self.async_socket.join()
			self.async_socket = None
	
	def connect_click(self):
		if not self.is_connected:
			# connect
			host = self.host_var.get().strip()
			if not host:
				self.log("Host must be not empty!")
				return
			try:
				port = self.port_var.get()
			except ValueError:
				self.log("Port must be an integer!")
				return
			is_udp = self.is_udp_var.get()
			# self.async_socket = AsyncSocket(host, port, is_udp, self.log, self.on_async_closed, self.on_recv)
			self.async_socket = SocketThread(is_udp)
			
			self.async_socket.on_exception = self.on_exception
			self.async_socket.on_connected = self.on_connected
			self.async_socket.on_disconnected = self.on_disconnected
			self.async_socket.on_recv = self.on_recv
			
			self.is_connected = True
			self.async_socket.connect((host, port))
			
			self.upd_interface(self.is_connected)
			self.send_e.focus_set()
		else:
			# disconnect
			self.do_disconnect()

def main():
	root = Tk()
	root.geometry("1000x600")
	app = AsyncSender(root)
	root.mainloop()

if __name__ == '__main__':
	main()
