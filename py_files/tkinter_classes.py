import logging as lg
import os
import pickle as pk
import tkinter as tk
import tkinter.messagebox
import tkinter.scrolledtext as st
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
        self.add_file_button = tk.Button(self.main_frame)
        self.delete_file_button = tk.Button(self.main_frame)

        # Customize GUI Components
        self.configure_components()

        # Grid Components
        self.grid_components()

        # Populate Tree
        self.update_file_tree()

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

        self.add_file_button.config(
            text='Add File',
            command=self.create_password_file
        )

        self.delete_file_button.config(
            text='Delete File',
            command=self.delete_password_file
        )

    def delete_password_file(self):
        window = tk.Toplevel()
        window.wm_title('Delete File')

        l = tk.Label(window, text='Input the name of the file you would like to delete.')
        l.grid(row=0, column=0, columnspan=2)

        file_name_label = tk.Label(window, text='File Name:')
        file_name_label.grid(column=0, row=1)

        file_name_entry = tk.Entry(window)
        file_name_entry.grid(column=1, row=1)

        def submit_record(window):
            if not file_name_entry.get():
                tk.messagebox.showerror('Input Error', 'Please input the name of the file you would like to delete.')
                return

            directory = os.fsencode(os.getcwd() + '\\resources')

            for file in os.listdir(directory):
                filename = os.fsdecode(file)
                if filename.endswith('.pk'):
                    if file_name_entry.get() in filename:
                        os.remove(os.getcwd() + '\\resources\\' + filename)

            self.update_file_tree()
            window.destroy()

        b = tk.Button(window, text='Delete', command=lambda: submit_record(window))
        b.grid(column=0, row=2, columnspan=2)

    def create_password_file(self):
        window = tk.Toplevel()
        window.wm_title('Create File')

        l = tk.Label(window, text='Input the name of the file you would like to create.')
        l.grid(row=0, column=0, columnspan=2)

        file_name_label = tk.Label(window, text='File Name:')
        file_name_label.grid(column=0, row=1)

        file_name_entry = tk.Entry(window)
        file_name_entry.grid(column=1, row=1)

        def submit_record(window):
            if not file_name_entry.get():
                tk.messagebox.showerror('Input Error', 'Please input the name of the file you would like to create.')
                return

            temp_list = list()

            with open(os.getcwd() + '\\resources\\' + file_name_entry.get() + '.pk', 'wb') as f:
                pk.dump(temp_list, f)
            self.update_file_tree()
            window.destroy()

        b = tk.Button(window, text='Create', command=lambda: submit_record(window))
        b.grid(column=0, row=2, columnspan=2)

    def open_password_file(self, event):
        clicked_file_name = self.password_files_tree.item(self.password_files_tree.focus())['text']
        self.pv.password_file_name = clicked_file_name
        self.pv.password_file_path = os.getcwd()

        inner_root = tk.Tk()
        AuthRecordViewer(inner_root, self.pv, self, clicked_file_name, )
        inner_root.mainloop()

    def update_file_tree(self):
        self.password_files_tree.delete(*self.password_files_tree.get_children())

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
        self.add_file_button.grid(column=0, row=3, sticky=tk.NSEW)
        self.delete_file_button.grid(column=1, row=3, sticky=tk.NSEW)

    def end_password_vault(self):
        self.pv.save_file()
        self.master.destroy()
