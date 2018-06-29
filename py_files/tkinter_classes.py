import logging as lg
import os
import pickle as pk
import tkinter as tk
import tkinter.filedialog
import tkinter.messagebox
import tkinter.scrolledtext as st
import tkinter.simpledialog
from tkinter import ttk


class AuthRecordViewer(object):
    def __init__(self, master, pv, file_viewer, clicked_file_name):
        self.master = master
        self.clicked_file_name = clicked_file_name
        self.file_viewer = file_viewer
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

        self.update_auth_record_tree()

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

    def update_auth_record_tree(self):
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
            self.update_auth_record_tree()
            self.file_viewer.update_file_tree()
            window.destroy()

        b = tk.Button(window, text='Submit', command=lambda: submit_record(window))
        b.grid(column=0, row=4, columnspan=2)

    def delete_record_form(self):
        window = tk.Toplevel()
        window.wm_title('Delete Record')

        l = tk.Label(window,
                     text='Input the system of the auth record you want to delete from ' + self.clicked_file_name + '.')
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
            self.update_auth_record_tree()
            self.file_viewer.update_file_tree()
            window.destroy()

        b = tk.Button(window, text='Submit', command=lambda: submit_record(window))
        b.grid(column=0, row=2, columnspan=2)

    def add_record_form(self):
        window = tk.Toplevel()
        window.wm_title('Add Record')

        l = tk.Label(window, text='Input the following three fields to add a record to ' + self.clicked_file_name + '.')
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
            self.update_auth_record_tree()
            self.file_viewer.update_file_tree()
            window.destroy()

        b = tk.Button(window, text='Submit', command=lambda: submit_record(window))
        b.grid(column=0, row=4, columnspan=2)


class PasswordFileViewer(object):
    def __init__(self, master, pv):
        self.master = master
        master.title('PasswordVault')
        self.master.protocol('WM_DELETE_WINDOW', self.end_password_vault)

        # Declare GUI Variables
        self.pv = pv

        # Declare GUI Components
        self.main_frame = tk.Frame(self.master)
        self.passwords_tree = ttk.Treeview(self.main_frame)
        self.debug_info = st.ScrolledText(self.main_frame)
        self.open_password_file_button = tk.Button(self.main_frame)
        self.create_password_file_button = tk.Button(self.main_frame)
        self.delete_password_file_button = tk.Button(self.main_frame)
        self.add_auth_record_button = tk.Button(self.main_frame)
        self.delete_auth_record_button = tk.Button(self.main_frame)

        # Customize GUI Components
        self.configure_components()

        # Grid Components
        self.grid_components()

    def configure_components(self):
        tk.Grid.columnconfigure(self.master, 0, weight=1)
        tk.Grid.rowconfigure(self.master, 0, weight=1)

        tk.Grid.columnconfigure(self.main_frame, 0, weight=1)
        tk.Grid.columnconfigure(self.main_frame, 1, weight=1)
        tk.Grid.rowconfigure(self.main_frame, 0, weight=1)
        # tk.Grid.rowconfigure(self.main_frame, 1, weight=1)
        tk.Grid.rowconfigure(self.main_frame, 2, weight=1)
        tk.Grid.rowconfigure(self.main_frame, 3, weight=1)
        tk.Grid.rowconfigure(self.main_frame, 4, weight=1)

        self.passwords_tree['columns'] = ('user', 'pass')
        self.passwords_tree['height'] = 10

        self.passwords_tree.column('#0', minwidth=100, width=100, stretch=True)
        self.passwords_tree.column('user', minwidth=100, width=100, stretch=True)
        self.passwords_tree.column('pass', minwidth=100, width=100, stretch=True)

        self.passwords_tree.heading('#0', text='System')
        self.passwords_tree.heading('user', text='Username')
        self.passwords_tree.heading('pass', text='Password')

        self.passwords_tree.bind('<Double-Button-1>', self.edit_auth_record)

        self.debug_info.config(
            state='disabled',
            font='TkFixedFont',
            wrap=tk.WORD
        )
        self.debug_info.tag_config('warning', foreground='red')

        self.open_password_file_button.config(
            text='Open File',
            command=self.open_password_file
        )

        self.create_password_file_button.config(
            text='Create File',
            command=self.create_password_file
        )

        self.delete_password_file_button.config(
            text='Delete File',
            command=self.delete_password_file
        )

        self.add_auth_record_button.config(
            text='+',
            command=self.add_auth_record,
            height=1,
            width=2
        )

        self.delete_auth_record_button.config(
            text='-',
            command=self.delete_auth_record,
            height=1,
            width=2
        )

    def grid_components(self):
        self.main_frame.grid(column=0, row=0, sticky=tk.NSEW)
        self.debug_info.grid(column=0, row=0, rowspan=5, sticky=tk.NSEW)
        self.passwords_tree.grid(column=1, row=0, rowspan=2, sticky=tk.NSEW)
        self.open_password_file_button.grid(column=1, row=2, sticky=tk.NSEW)
        self.create_password_file_button.grid(column=1, row=3, sticky=tk.NSEW)
        self.delete_password_file_button.grid(column=1, row=4, sticky=tk.NSEW)
        self.add_auth_record_button.grid(column=2, row=0, sticky=tk.S)
        self.delete_auth_record_button.grid(column=2, row=1, sticky=tk.N)

    def open_password_file(self):
        file_path = tk.filedialog.askopenfile()

        if not file_path:
            lg.warning('Please select a file to open!')
        else:
            self.pv.password_file_name = file_path.name.split('/')[-1].split('.')[0]
            self.pv.password_file_path = '/'.join(file_path.name.split('/')[0:-1]) + '/'

            self.pv.open_password_file()

            self.update_file_tree()

    def create_password_file(self):
        file_path = tk.filedialog.askdirectory()

        if not file_path:
            lg.warning('Please select a folder to save your file!')
        else:
            self.pv.password_file_path = file_path + '/'

            ans = tk.simpledialog.askstring('File Name', 'Please enter the name for your password file.')

            if not ans:
                lg.warning('Please enter a name for your password file!')
            else:
                self.pv.password_file_name = ans

                self.pv.create_password_file()

    def delete_password_file(self):
        lg.error('Sorry this function has not been implemented yet!')

    def update_file_tree(self):
        self.passwords_tree.delete(*self.passwords_tree.get_children())

        self.pv.data_base_cursor.execute('SELECT * FROM auth_records')

        fetch_result = self.pv.data_base_cursor.fetchall()

        for auth_record in fetch_result:
            self.passwords_tree.insert('', 0, text=auth_record[0], values=(auth_record[1], auth_record[2]))

    def add_auth_record(self):
        if None in [self.pv.password_file_path, self.pv.password_file_name]:
            lg.warning('Please open or create a password file before trying to add an authentication record!')
            return

        window = tk.Toplevel()
        window.wm_title('Add Record')

        l = tk.Label(window,
                     text='Input the following three fields to add a record to ' + self.pv.password_file_name + '.')
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
            self.update_file_tree()
            window.destroy()

        b = tk.Button(window, text='Submit', command=lambda: submit_record(window))
        b.grid(column=0, row=4, columnspan=2)

    def edit_auth_record(self, event):
        auth_record_window = tk.Toplevel()
        auth_record_window.wm_title('Edit Record')

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
            self.update_auth_record_tree()
            self.file_viewer.update_file_tree()
            window.destroy()

        b = tk.Button(window, text='Submit', command=lambda: submit_record(window))
        b.grid(column=0, row=4, columnspan=2)

    def delete_auth_record(self):
        if None in [self.pv.password_file_path, self.pv.password_file_name]:
            lg.warning('Please open or create a password file before trying to add an authentication record!')
            return

        window = tk.Toplevel()
        window.wm_title('Delete Record')

        l = tk.Label(window,
                     text='Input the system of the auth record you want to delete from ' + self.pv.password_file_name + '.')
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
            self.update_file_tree()
            window.destroy()

        b = tk.Button(window, text='Submit', command=lambda: submit_record(window))
        b.grid(column=0, row=2, columnspan=2)

    def end_password_vault(self):
        self.pv.save_password_file()
        self.master.destroy()
