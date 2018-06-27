import base64 as b64
import logging as lg
import os
import pickle as pk
import tkinter as tk
import tkinter.messagebox
import tkinter.scrolledtext as st
from logging import FileHandler
from tkinter import ttk


class AuthRecordViewer(object):
    def __init__(self, master, pv, clicked_file_name):
        self.master = master
        self.clicked_file_name = clicked_file_name
        master.wm_title(self.clicked_file_name)

        # Variables
        self.pv = pv
        with open(os.getcwd() + '\\resources\\' + self.clicked_file_name, 'rb') as f:
            self.pv.auth_record_list = pk.load(f)

        # Declare GUI Components
        self.main_frame = tk.Frame(self.master)
        self.passwords_tree = ttk.Treeview(self.main_frame)
        self.add_record_button = tk.Button(self.main_frame)
        self.view_records_button = tk.Button(self.main_frame)
        self.delete_record_button = tk.Button(self.main_frame)
        self.edit_record_button = tk.Button(self.main_frame)

        # Customize GUI Components
        self.configure_components()

        # Grid Components
        self.grid_components()

        self.update_tree()

    def configure_components(self):
        tk.Grid.columnconfigure(self.master, 0, weight=1)
        tk.Grid.rowconfigure(self.master, 0, weight=1)

        tk.Grid.columnconfigure(self.main_frame, 0, weight=1)
        tk.Grid.rowconfigure(self.main_frame, 0, weight=1)
        tk.Grid.rowconfigure(self.main_frame, 1, weight=1)
        tk.Grid.rowconfigure(self.main_frame, 2, weight=1)

        self.passwords_tree['columns'] = ('user', 'pass')
        self.passwords_tree['height'] = 10

        self.passwords_tree.column('#0', minwidth=100, width=100, stretch=True)
        self.passwords_tree.column('user', minwidth=100, width=100, stretch=True)
        self.passwords_tree.column('pass', minwidth=100, width=100, stretch=True)

        self.passwords_tree.heading('#0', text='System')
        self.passwords_tree.heading('user', text='Username')
        self.passwords_tree.heading('pass', text='Password')

        self.passwords_tree.bind('<Double-Button-1>', self.edit_auth_record)

        self.add_record_button.config(
            text='Add Record',
            command=self.add_record_form
        )

        self.delete_record_button.config(
            text='Delete Record',
            command=self.delete_record_form
        )

    def grid_components(self):
        self.main_frame.grid(column=0, row=0, sticky=tk.NSEW)
        self.passwords_tree.grid(column=0, row=0, columnspan=2, sticky=tk.NSEW)
        self.add_record_button.grid(column=0, row=3, sticky=tk.NSEW)
        self.delete_record_button.grid(column=0, row=4, sticky=tk.NSEW)

    def update_tree(self):
        self.passwords_tree.delete(*self.passwords_tree.get_children())
        for auth_record_object in self.pv.auth_record_list:
            self.passwords_tree.insert('', 0, text=auth_record_object.system,
                                       values=(auth_record_object.username, auth_record_object.password))

    def edit_auth_record(self, event):
        window = tk.Toplevel()
        window.wm_title('Edit Record')

        l = tk.Label(window, text='Please enter the new information for this auth record.')
        l.grid(row=0, column=0, columnspan=2)

        username_label = tk.Label(window, text='New Username:')
        username_label.grid(column=0, row=2)

        username_entry = tk.Entry(window)
        username_entry.grid(column=1, row=2)

        password_label = tk.Label(window, text='New Password:')
        password_label.grid(column=0, row=3)

        password_entry = tk.Entry(window, show='*')
        password_entry.grid(column=1, row=3)

        def submit_record(window):
            self.pv.edit_auth_record(self.passwords_tree.item(self.passwords_tree.focus())['text'],
                                     username_entry.get(), password_entry.get())
            self.update_tree()
            window.destroy()

        b = tk.Button(window, text='Submit', command=lambda: submit_record(window))
        b.grid(column=0, row=4, columnspan=2)

    def delete_record_form(self):
        window = tk.Toplevel()
        window.wm_title('Delete Record')

        l = tk.Label(window, text='Input the system of the auth record you want to delete from the _PasswordVault.')
        l.grid(row=0, column=0, columnspan=2)

        sys_label = tk.Label(window, text='System:')
        sys_label.grid(column=0, row=1)

        sys_entry = tk.Entry(window)
        sys_entry.grid(column=1, row=1)

        def submit_record(window):
            if not sys_entry.get():
                tk.messagebox.showerror('Input Error', 'Please input the system of the auth record you want to delete.')
                return

            self.pv.delete_auth_record(sys_entry.get())
            self.update_tree()
            window.destroy()

        b = tk.Button(window, text='Submit', command=lambda: submit_record(window))
        b.grid(column=0, row=2, columnspan=2)

    def add_record_form(self):
        window = tk.Toplevel()
        window.wm_title('Add Record')

        l = tk.Label(window, text='Input the following three fields to add a record to the _PasswordVault.')
        l.grid(row=0, column=0, columnspan=2)

        sys_label = tk.Label(window, text='System:')
        sys_label.grid(column=0, row=1)

        sys_entry = tk.Entry(window)
        sys_entry.grid(column=1, row=1)

        username_label = tk.Label(window, text='Username:')
        username_label.grid(column=0, row=2)

        username_entry = tk.Entry(window)
        username_entry.grid(column=1, row=2)

        password_label = tk.Label(window, text='Password:')
        password_label.grid(column=0, row=3)

        password_entry = tk.Entry(window, show='*')
        password_entry.grid(column=1, row=3)

        def submit_record(window):
            if not (sys_entry.get() and username_entry.get() and password_entry.get()):
                tk.messagebox.showerror('Input Error', 'Please fill all fields to add an auth record.')
                return

            self.pv.add_auth_record(sys_entry.get(), username_entry.get(), password_entry.get())
            self.update_tree()
            window.destroy()

        b = tk.Button(window, text='Submit', command=lambda: submit_record(window))
        b.grid(column=0, row=4, columnspan=2)


class PasswordFilesViewer(object):
    def __init__(self, master, pv):
        self.master = master
        master.title('_PasswordVault')
        self.master.protocol('WM_DELETE_WINDOW', self.end_password_vault)

        # Declare GUI Variables
        self.pv = pv

        # Declare GUI Components
        self.main_frame = tk.Frame(self.master)
        self.title_label = tk.Label(self.main_frame)
        self.password_files_tree = ttk.Treeview(self.main_frame)
        self.debug_info = st.ScrolledText(self.main_frame)

        # Customize GUI Components
        self.configure_components()

        # Grid Components
        self.grid_components()

        # Populate Tree
        self.populate_password_files_tree()

    def configure_components(self):
        tk.Grid.columnconfigure(self.master, 0, weight=1)
        tk.Grid.rowconfigure(self.master, 0, weight=1)

        tk.Grid.columnconfigure(self.main_frame, 0, weight=1)
        tk.Grid.rowconfigure(self.main_frame, 0, weight=1)
        tk.Grid.rowconfigure(self.main_frame, 1, weight=1)
        tk.Grid.rowconfigure(self.main_frame, 2, weight=1)

        self.title_label.config(
            text='Please select the options you want below.'
        )

        self.password_files_tree['columns'] = ('num')
        self.password_files_tree['height'] = 5

        self.password_files_tree.column('#0', minwidth=100, width=200, stretch=True)
        self.password_files_tree.column('num', minwidth=100, width=100, stretch=False)

        self.password_files_tree.heading('#0', text='File Name')
        self.password_files_tree.heading('num', text='# of Passwords')

        self.password_files_tree.bind('<Double-Button-1>', self.open_password_file)

        self.debug_info.config(
            state='disabled',
            font='TkFixedFont',
            wrap=tk.WORD
        )
        self.debug_info.tag_config('warning', foreground='red')

    def open_password_file(self, event):
        clicked_file_name = self.password_files_tree.item(self.password_files_tree.focus())['text']
        self.pv.file_name = clicked_file_name

        inner_root = tk.Tk()
        AuthRecordViewer(inner_root, self.pv, clicked_file_name)
        inner_root.mainloop()

    def populate_password_files_tree(self):
        directory = os.fsencode(os.getcwd() + '\\resources')

        for file in os.listdir(directory):
            filename = os.fsdecode(file)
            if filename.endswith('.pk'):
                with open(os.getcwd() + '\\resources\\' + filename, 'rb') as f:
                    temp_list = pk.load(f)

                    self.password_files_tree.insert('', 0, text=filename, values=(len(temp_list)))

        if len(self.password_files_tree.get_children()) == 0:
            lg.error('Could not find any old password files!')

    def grid_components(self):
        self.main_frame.grid(column=0, row=0, sticky=tk.NSEW)
        self.title_label.grid(column=0, row=0, columnspan=2)
        self.password_files_tree.grid(column=0, row=1, columnspan=2, sticky=tk.NSEW)
        self.debug_info.grid(column=0, row=2, columnspan=2, sticky=tk.NSEW)

    def end_password_vault(self):
        self.pv.generate_byte_file()
        self.master.destroy()


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


class AuthRecord(object):
    def __init__(self, inc_system, inc_username, inc_password):
        self.system = inc_system
        self.username = inc_username
        self.password = ''
        self.encrypt_password(inc_password)

    def get_username(self):
        return self.username

    def encrypt_password(self, inc_password):
        self.password = b64.b64encode(inc_password.encode('utf-8'))

    def get_password(self):
        return b64.b64decode(self.password).decode('utf-8')


class PasswordVault(object):

    def __init__(self, master=None, filename=None):
        self.gui_mode = False

        self.file_name = filename

        self.auth_record_list = list()

        if master is not None:
            self.gui_mode = True
            self.file_viewer_gui = PasswordFilesViewer(master, self)
        elif self.file_name is None:
            lg.error('A targeted filename is required if not running in GUI mode!')
        else:
            self.populate_from_existing_byte_file(self.file_name)

        self.logging_setup()

    def logging_setup(self):
        if self.gui_mode:
            texthandler = TextHandler(self.file_viewer_gui.debug_info)

            logger = lg.getLogger()
            logger.setLevel(lg.INFO)
            logger.addHandler(texthandler)
        else:
            log_file_formatter = lg.Formatter(
                "[%(asctime)s] [%(levelname)-8s]: %(message)s (%(funcName)s:%(lineno)s)",
                datefmt='%m/%d/%Y %I:%M:%S%p'
            )
            log_file_handler = FileHandler(
                'resources\PasswordVault.log',
                mode='w'
            )
            log_file_handler.setFormatter(log_file_formatter)
            logger = lg.getLogger()
            logger.setLevel(lg.INFO)
            logger.addHandler(log_file_handler)

    def populate_from_existing_byte_file(self, filename):
        if os.path.exists('resources/' + filename):
            try:
                with open('resources/' + filename, 'rb') as f:
                    self.auth_record_list = pk.load(f)
            except OSError as e:
                lg.error('Error: %s - %s.', e.filename, e.strerror)
        else:
            lg.info('Did not find an existing password file.')

    def generate_byte_file(self):
        with open('resources/password_vault_passwords.pk', 'wb') as f:
            pk.dump(self.auth_record_list, f)

    def get_auth_record(self, inc_system):
        for auth_record_object in self.auth_record_list:
            if auth_record_object.system == inc_system:
                return auth_record_object
        lg.warning('Could not find an authentication record for %s in %s', inc_system, self.file_name)

    def add_auth_record(self, inc_system, inc_username, inc_password):
        for auth_record_object in self.auth_record_list:
            if auth_record_object.system == inc_system:
                lg.error('Already have a record for %s in %s. Please edit the existing record.', inc_system,
                         self.file_name)
                return
        self.auth_record_list.append(AuthRecord(inc_system, inc_username, inc_password))
        lg.info('Successfully added %s to %s.', inc_system, self.file_name)

    def delete_auth_record(self, inc_system):
        removed = False
        for auth_record_object in self.auth_record_list:
            if auth_record_object.system == inc_system:
                try:
                    self.auth_record_list.remove(auth_record_object)
                    removed = True
                except ValueError:
                    lg.error('Could not find an authentication record for that system in %s.', self.file_name)

        if removed:
            lg.info('Successfully deleted the auth record %s in %s', inc_system, self.file_name)
        else:
            lg.warning('Could not delete that authentication record because I could not find it in %s.', self.file_name)

    def edit_auth_record(self, inc_system, inc_username, inc_password):
        found = False
        for auth_record_object in self.auth_record_list:
            if auth_record_object.system == inc_system:
                if inc_username:
                    auth_record_object.username = inc_username
                if inc_password:
                    auth_record_object.encrypt_password(inc_password)
                found = True

        if found:
            lg.info('Successfully edited the %s entry in %s.', inc_system, self.file_name)
        else:
            lg.warning('Could not find an entry with the system %s!', inc_system)

    def list_records(self):
        if self.gui_mode:
            lg.info('\nThese systems have a record in %s:', self.file_name)
            for auth_record_object in self.auth_record_list:
                lg.info('%s', auth_record_object.system)
        else:
            lg.warning('This function is not supported in program mode yet!')


if __name__ == '__main__':
    root = tk.Tk()
    PasswordVault(root)
    root.mainloop()

    # pv = _PasswordVault()
    #
    # print(pv.get_auth_record('personal_ad').username)
    # print(pv.get_auth_record('personal_ad').password)
    # print(pv.get_auth_record('personal_ad').get_password())
