import logging as lg
import os
import sqlite3 as sq
import sys
import tkinter as tk

import pandas as pd
import pendulum as pend
from cryptography.fernet import Fernet
from py_files.logging_classes import TextHandler
from py_files.tkinter_classes import PasswordFileViewer


class PasswordVault(object):

    def __init__(self, master=None, file_path=None, file_name=None):
        self.gui_mode = False

        self.password_file_path = file_path

        self.password_file_name = file_name

        self.data_base_connection = None

        self.data_base_cursor = None

        if master is not None:
            if self.password_file_path is None:
                self.password_file_path = './resources/'

            self.gui_mode = True
            self.file_viewer_gui = PasswordFileViewer(master, self)
            self.logging_setup()
        elif None in [self.password_file_path, self.password_file_name]:
            lg.error('A file name and its path are required if not running in GUI mode!')
        else:
            self.logging_setup()

            self.open_password_file()

    def logging_setup(self):
        if self.gui_mode:
            text_handler = TextHandler(self.file_viewer_gui.debug_info)

            logger = lg.getLogger()
            logger.setLevel(lg.INFO)
            logger.addHandler(text_handler)
        else:
            log_formatter = lg.Formatter("[%(funcName)s] [%(levelname)s] %(message)s")
            logger = lg.getLogger()

            console_handler = lg.StreamHandler()
            console_handler.setFormatter(log_formatter)
            logger.addHandler(console_handler)
            logger.setLevel(lg.INFO)

    def create_password_file(self):
        if os.path.exists(self.password_file_path + self.password_file_name + '.db'):
            self.open_password_file()
            return
        try:
            self.data_base_connection = sq.connect(self.password_file_path + self.password_file_name + '.db')
            self.data_base_cursor = self.data_base_connection.cursor()
            self.data_base_cursor.execute(
                'CREATE TABLE auth_records (system text, username text, token text, key text, date text)')
            self.data_base_cursor.execute('CREATE UNIQUE INDEX system ON auth_records(username, token, key)')

            lg.info('Created a new password file called %s in %s', self.password_file_name, self.password_file_path)
        except Exception as e:
            lg.error('%s: %s', sys.exc_info()[0], e)

    def open_password_file(self):
        if not os.path.exists(self.password_file_path + self.password_file_name + '.db'):
            self.create_password_file()
            return
        try:
            self.data_base_connection = sq.connect(self.password_file_path + self.password_file_name + '.db')
            self.data_base_cursor = self.data_base_connection.cursor()

            if self.gui_mode:
                self.file_viewer_gui.update_file_tree()

            lg.info('Opened up the password file %s in %s', self.password_file_name, self.password_file_path)
        except Exception as e:
            lg.error('%s: %s', sys.exc_info()[0], e)

    def delete_password_file(self):
        if not os.path.exists(self.password_file_path + self.password_file_name + '.db'):
            lg.error(f'Cannot find {self.password_file_name} in {self.password_file_path}.')
        else:
            os.remove(self.password_file_path + self.password_file_name + '.db')

    def save_password_file(self):
        if self.data_base_connection is not None:
            self.data_base_connection.close()

        lg.info('Closed connection to %s', self.password_file_name)

    def get_auth_record(self, inc_system):
        try:
            self.data_base_cursor.execute("SELECT * FROM auth_records WHERE system=?", (inc_system,))
            fetch_results = self.data_base_cursor.fetchone()

            if fetch_results:
                f = Fernet(fetch_results[3])
                return fetch_results[1], f.decrypt(fetch_results[2]).decode()
            else:
                lg.error('Could not find system %s in %s', inc_system, self.password_file_name)
        except Exception as e:
            lg.error('%s: %s', sys.exc_info()[0], e)

    def add_auth_record(self, inc_system, inc_username, inc_password):
        try:
            key = Fernet.generate_key()
            f = Fernet(key)
            token = f.encrypt(inc_password.encode())

            dt = pend.now()

            self.data_base_cursor.execute("INSERT INTO auth_records VALUES (?, ?, ?, ?, ?)",
                                          (inc_system, inc_username, token, key, dt.format('YYYY-MM-DD HH:mm:ss')))
            self.data_base_connection.commit()

            lg.info('Successfully added %s to %s.', inc_system, self.password_file_name)
        except sq.IntegrityError as e:
            if 'UNIQUE' in str(e):
                lg.warning(
                    '''An entry with the system %s already exists in  %s, 
                    please edit it or create a new record with a different system''',
                    inc_system,
                    self.password_file_name
                )
            else:
                lg.error('%s: %s', sys.exc_info()[0], e)
        except Exception as e:
            lg.error('%s: %s', sys.exc_info()[0], e)

    def delete_auth_record(self, inc_system):
        try:
            self.data_base_cursor.execute("SELECT * FROM auth_records where system=?", (inc_system,))
            is_there = self.data_base_cursor.fetchone()

            if is_there:
                self.data_base_cursor.execute("DELETE FROM auth_records WHERE system=?", (inc_system,))
                self.data_base_connection.commit()
                lg.info('Successfully deleted %s from %s.', inc_system, self.password_file_name)
            else:
                lg.error('The system %s does not exist in the file, and therefore cannot be deleted', inc_system)
        except Exception as e:
            lg.error('%s: %s', sys.exc_info()[0], e)

    def edit_auth_record(self, inc_system, inc_username, inc_password):
        try:
            self.data_base_cursor.execute("SELECT * FROM auth_records where system=?", (inc_system,))
            is_there = self.data_base_cursor.fetchone()

            if is_there:
                if not inc_password:
                    self.data_base_cursor.execute("UPDATE auth_records SET username=? WHERE system=?",
                                                  (inc_username, inc_system))
                if not inc_username:
                    key = Fernet.generate_key()
                    f = Fernet(key)
                    token = f.encrypt(inc_password.encode())

                    self.data_base_cursor.execute("UPDATE auth_records SET token=?, key=? WHERE system=?",
                                                  (token, key, inc_system))
                else:
                    key = Fernet.generate_key()
                    f = Fernet(key)
                    token = f.encrypt(inc_password.encode())

                    self.data_base_cursor.execute("UPDATE auth_records SET username=?, token=?, key=? WHERE system=?",
                                                  (inc_username, token, key, inc_system))
                self.data_base_connection.commit()
                lg.info('Successfully edited %s in %s', inc_system, self.password_file_name)
            else:
                lg.error('The system %s does not exist in the file, and therefore cannot be edited', inc_system)

        except Exception as e:
            lg.error('%s: %s', sys.exc_info()[0], e)

    def list_records(self):
        try:
            df = pd.read_sql_query("SELECT * FROM auth_records", self.data_base_connection)
            with pd.option_context('display.max_rows', None, 'display.max_columns', None):
                print(df)
        except Exception as e:
            lg.error('%s: %s', sys.exc_info()[0], e)


if __name__ == '__main__':
    root = tk.Tk()
    PasswordVault(root)
    root.mainloop()

    # pv = PasswordVault(file_path='./resources/', file_name='test')
    #
    # # pv.add_auth_record('test_system_1', 'test_username_1', 'test_password_1')
    #
    # # pv.add_auth_record('test_system_2', 'test_username_2', 'test_password_2')
    #
    # # pv.list_records()
    #
    # # pv.edit_auth_record('test_system', '', '')
    # # pv.edit_auth_record('test_system', 'new_test_user', 'new_test_pass')
    #
    # # pv.list_records()
    #
    # print(pv.get_auth_record('test_system_1'))
    #
    # pv.save_password_file()
