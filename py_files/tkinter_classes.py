import logging as lg
import tkinter as tk
import tkinter.filedialog
import tkinter.messagebox
import tkinter.scrolledtext as st
import tkinter.simpledialog
from tkinter import ttk


class PasswordFileViewer(object):
    def __init__(self, master, pv):
        self.master = master
        master.title('PasswordVault')
        self.master.protocol('WM_DELETE_WINDOW', self.end_password_vault)
        self.master.minsize(1100, 500)

        # Declare GUI Variables
        self.pv = pv

        # Declare GUI Components
        self.main_frame = tk.Frame(self.master)
        self.passwords_tree = ttk.Treeview(self.main_frame)
        self.password_file_label = tk.Label(self.main_frame)
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
        # tk.Grid.rowconfigure(self.main_frame, 0, weight=1)
        tk.Grid.rowconfigure(self.main_frame, 1, weight=1)
        # tk.Grid.rowconfigure(self.main_frame, 2, weight=1)
        # tk.Grid.rowconfigure(self.main_frame, 3, weight=1)
        # tk.Grid.rowconfigure(self.main_frame, 4, weight=1)

        self.passwords_tree['columns'] = ('user', 'date')
        self.passwords_tree['height'] = 10

        self.passwords_tree.column('#0', anchor=tk.CENTER, minwidth=100, width=100, stretch=True)
        self.passwords_tree.column('user', anchor=tk.CENTER, minwidth=100, width=100, stretch=True)
        self.passwords_tree.column('date', anchor=tk.CENTER, minwidth=150, width=150, stretch=True)

        self.passwords_tree.heading('#0', text='System')
        self.passwords_tree.heading('user', text='Username')
        self.passwords_tree.heading('date', text='Creation Date')

        self.passwords_tree.bind('<Double-Button-1>', self.edit_auth_record)

        self.password_file_label.config(
            text='no password file selected',
            height=2
        )

        self.debug_info.config(
            state='disabled',
            font='TkFixedFont',
            wrap=tk.WORD,
            width=30
        )
        self.debug_info.tag_config('warning', foreground='red')

        self.open_password_file_button.config(
            text='Open File',
            command=self.open_password_file,
            height=2,
            font=('Georgia bold',),
            overrelief=tk.GROOVE
        )

        self.create_password_file_button.config(
            text='Create File',
            command=self.create_password_file,
            height=2,
            font=('Georgia bold',),
            overrelief=tk.GROOVE
        )

        self.delete_password_file_button.config(
            text='Delete File',
            command=self.delete_password_file,
            height=2,
            font=('Georgia bold',),
            overrelief=tk.GROOVE
        )

        self.add_auth_record_button.config(
            text='+',
            command=self.add_auth_record,
            height=1,
            width=2,
            font=('Georgia bold',),
            overrelief=tk.GROOVE
        )

        self.delete_auth_record_button.config(
            text='-',
            command=self.delete_auth_record,
            height=1,
            width=2,
            font=('Georgia bold',),
            overrelief=tk.GROOVE
        )

    def grid_components(self):
        self.main_frame.grid(column=0, row=0, sticky=tk.NSEW)

        self.debug_info.grid(column=0, row=0, rowspan=6, sticky=tk.NSEW)
        self.password_file_label.grid(column=1, row=0, columnspan=2)
        self.passwords_tree.grid(column=1, row=1, rowspan=2, sticky=tk.NSEW)
        self.open_password_file_button.grid(column=1, row=3, sticky=tk.NSEW)
        self.create_password_file_button.grid(column=1, row=4, sticky=tk.NSEW)
        self.delete_password_file_button.grid(column=1, row=5, sticky=tk.NSEW)
        self.add_auth_record_button.grid(column=2, row=1, sticky=tk.S)
        self.delete_auth_record_button.grid(column=2, row=2, sticky=tk.N)

    def open_password_file(self):
        file_path = tk.filedialog.askopenfile()

        if not file_path:
            lg.warning('Please select a file to open!')
        else:
            self.pv.password_file_name = file_path.name.split('/')[-1].split('.')[0]
            self.pv.password_file_path = '/'.join(file_path.name.split('/')[0:-1]) + '/'

            self.pv.open_password_file()

            self.update_file_tree()

            self.password_file_label['text'] = self.pv.password_file_name
            self.password_file_label['fg'] = 'Blue'
            self.password_file_label['font'] = ('Georgia bold', 14)

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

                self.password_file_label['text'] = self.pv.password_file_name
                self.password_file_label['fg'] = 'Blue'
                self.password_file_label['font'] = ('Georgia bold', 14)

    def delete_password_file(self):
        if None in [self.pv.password_file_path, self.pv.password_file_name]:
            lg.warning('Please open or create a password file before trying to delete it!')
            return

        if tk.messagebox.askyesno('Delete Record',
                                  f'Are you sure you want to delete {self.pv.password_file_name} from {self.pv.password_file_path}?'):
            self.passwords_tree.delete(*self.passwords_tree.get_children())
            self.pv.save_password_file()
            self.pv.delete_password_file()

            self.password_file_label['text'] = 'no password file selected'
            self.password_file_label['fg'] = 'black'
            self.password_file_label['font'] = 'TkDefaultFont'

    def update_file_tree(self):
        self.passwords_tree.delete(*self.passwords_tree.get_children())

        self.pv.data_base_cursor.execute('SELECT * FROM auth_records')

        fetch_result = self.pv.data_base_cursor.fetchall()

        for auth_record in fetch_result:
            self.passwords_tree.insert('', 0, text=auth_record[0], values=(auth_record[1], auth_record[4]))

    def add_auth_record(self):
        if None in [self.pv.password_file_path, self.pv.password_file_name]:
            tk.messagebox.showerror('Error',
                                    'Please open or create a password file before trying to add an authentication record.')
            return

        add_auth_record_window = tk.Toplevel()
        add_auth_record_window.wm_title('Add Record')

        l = tk.Label(add_auth_record_window,
                     text='Input the following three fields to add a record to ' + self.pv.password_file_name + '.')
        l.grid(row=0, column=0, columnspan=2)

        sys_label = tk.Label(add_auth_record_window, text='System:')
        sys_label.grid(column=0, row=1)

        sys_entry = tk.Entry(add_auth_record_window)
        sys_entry.grid(column=1, row=1)

        username_label = tk.Label(add_auth_record_window, text='Username:')
        username_label.grid(column=0, row=2)

        username_entry = tk.Entry(add_auth_record_window)
        username_entry.grid(column=1, row=2)

        password_label = tk.Label(add_auth_record_window, text='Password:')
        password_label.grid(column=0, row=3)

        password_entry = tk.Entry(add_auth_record_window, show='*')
        password_entry.grid(column=1, row=3)

        def submit_record(event=None):
            if not (sys_entry.get() and username_entry.get() and password_entry.get()):
                tk.messagebox.showerror('Input Error', 'Please fill all fields to add an auth record.')
                return

            self.pv.add_auth_record(sys_entry.get(), username_entry.get(), password_entry.get())
            self.update_file_tree()

            add_auth_record_window.destroy()

        add_auth_record_window.bind('<Return>', submit_record)

        b = tk.Button(add_auth_record_window, text='Submit', command=submit_record)
        b.grid(column=0, row=4, columnspan=2)

    def edit_auth_record(self, event=None):
        if None in [self.pv.password_file_path, self.pv.password_file_name]:
            tk.messagebox.showerror('Error',
                                    'Please open or create a password file before trying to edit an authentication record.')
            return

        if not self.passwords_tree.focus():
            tk.messagebox.showerror('Error', 'Please select an authentication record to edit.')
            return

        edit_auth_record_window = tk.Toplevel()
        edit_auth_record_window.wm_title('Edit Record')

        l = tk.Label(edit_auth_record_window, text='Please enter the new information for this auth record.')
        l.grid(row=0, column=0, columnspan=2)

        username_label = tk.Label(edit_auth_record_window, text='New Username:')
        username_label.grid(column=0, row=2)

        username_entry = tk.Entry(edit_auth_record_window)
        username_entry.grid(column=1, row=2)

        password_label = tk.Label(edit_auth_record_window, text='New Password:')
        password_label.grid(column=0, row=3)

        password_entry = tk.Entry(edit_auth_record_window, show='*')
        password_entry.grid(column=1, row=3)

        def submit_record(event=None):
            self.pv.edit_auth_record(self.passwords_tree.item(self.passwords_tree.focus())['text'],
                                     username_entry.get(), password_entry.get())
            self.update_file_tree()
            edit_auth_record_window.destroy()

        edit_auth_record_window.bind('<Return>', submit_record)

        b = tk.Button(edit_auth_record_window, text='Submit', command=submit_record)
        b.grid(column=0, row=4, columnspan=2)

    def delete_auth_record(self):
        if None in [self.pv.password_file_path, self.pv.password_file_name]:
            tk.messagebox.showerror('Error',
                                    'Please open or create a password file before trying to delete an authentication record.')
            return

        if not self.passwords_tree.focus():
            tk.messagebox.showerror('Error', 'Please select an authentication record to delete.')
            return

        selected_item = self.passwords_tree.focus()

        auth_record_system = self.passwords_tree.item(selected_item, 'text')

        if tk.messagebox.askyesno('Delete Record',
                                  f'Are you sure you want to delete {auth_record_system} from {self.pv.password_file_name}?'):
            self.pv.delete_auth_record(auth_record_system)
            self.passwords_tree.delete(selected_item)

    def end_password_vault(self):
        self.pv.save_password_file()
        self.master.destroy()
