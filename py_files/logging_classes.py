import logging as lg
import tkinter as tk


class TextHandler(lg.Handler):
    def __init__(self, text):
        lg.Handler.__init__(self)
        self.text = text

    def emit(self, record):
        msg_level = record.levelname
        msg = self.format(record)

        def append():
            self.text.configure(state='normal')
            if msg_level in ['WARNING', 'ERROR']:
                self.text.insert(tk.END, msg + '\n', 'warning')
            else:
                self.text.insert(tk.END, msg + '\n')
            self.text.configure(state='disabled')
            self.text.yview(tk.END)

        self.text.after(0, append)
