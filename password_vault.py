import base64 as b64
import logging as lg
import os
import pickle as pk
import tkinter as tk

from py_files.logging_classes import TextHandler
from py_files.tkinter_classes import PasswordFilesViewer


class PasswordVault(object):
    class AuthRecord(object):
        def __init__(self, inc_system, inc_username, inc_password):
            self.system = inc_system
            self.username = inc_username

            self.encrypt_password(inc_password)

        def get_username(self):
            return self.username

        def encrypt_password(self, inc_password):
            self.password = b64.b64encode(inc_password.encode('utf-8'))

        def get_password(self):
            return b64.b64decode(self.password).decode('utf-8')

    def __init__(self, master=None, file_path=None, file_name=None):
        self.gui_mode = False

        self.password_file_path = file_path

        self.password_file_name = file_name

        self.auth_records_list = list()

        if master is not None:
            self.gui_mode = True
            self.file_viewer_gui = PasswordFilesViewer(master, self)
            self.gui_logging_setup()
        elif None in [self.password_file_path, self.password_file_name]:
            lg.error('A file name and its path are required if not running in GUI mode!')
        else:
            if os.path.exists(self.password_file_path + self.password_file_name):
                self.load_existing_password_file()
            elif os.path.exists(self.password_file_path):
                self.create_new_password_file()

    def gui_logging_setup(self):
        if self.gui_mode:
            text_handler = TextHandler(self.file_viewer_gui.debug_info)

            logger = lg.getLogger()
            logger.setLevel(lg.INFO)
            logger.addHandler(text_handler)

    def create_new_password_file(self):
        try:
            with open(self.password_file_path + self.password_file_name, 'wb') as f:
                pk.dump(self.auth_records_list, f)
            lg.info('Created new password file: %s', self.password_file_name)
        except OSError as e:
            lg.error('Error: %s - %s.', e.filename, e.strerror)

    def load_existing_password_file(self):
        try:
            with open(self.password_file_path + self.password_file_name, 'rb') as f:
                self.auth_records_list = pk.load(f)
            lg.info('Loaded %s with %s passwords.', self.password_file_name, str(len(self.auth_records_list)))
        except OSError as e:
            lg.error('Error: %s - %s.', e.filename, e.strerror)

    def save_file(self):
        try:
            with open(self.password_file_path + self.password_file_name, 'wb') as f:
                pk.dump(self.auth_records_list, f)
        except OSError as e:
            lg.error('Error: %s - %s.', e.filename, e.strerror)

    def get_auth_record(self, inc_system):
        for auth_record_object in self.auth_records_list:
            if auth_record_object.system == inc_system:
                return auth_record_object
        lg.warning('Could not find an authentication record for %s in %s', inc_system, self.password_file_name)

    def add_auth_record(self, inc_system, inc_username, inc_password):
        for auth_record_object in self.auth_records_list:
            if auth_record_object.system == inc_system:
                lg.error('Already have a record for %s in %s. Please edit the existing record.', inc_system,
                         self.password_file_path)
                return
        self.auth_records_list.append(self.AuthRecord(inc_system, inc_username, inc_password))
        self.save_file()
        lg.info('Successfully added %s to %s.', inc_system, self.password_file_path)

    def delete_auth_record(self, inc_system):
        removed = False
        for auth_record_object in self.auth_records_list:
            if auth_record_object.system == inc_system:
                try:
                    self.auth_records_list.remove(auth_record_object)
                    removed = True
                except ValueError:
                    lg.error('Could not find an authentication record for that system in %s.', self.password_file_path)
        if removed:
            lg.info('Successfully deleted the auth record %s in %s', inc_system, self.password_file_path)
            self.save_file()
        else:
            lg.warning('Could not delete that authentication record because I could not find it in %s.',
                       self.password_file_path)

    def edit_auth_record(self, inc_system, inc_username, inc_password):
        found = False
        for auth_record_object in self.auth_records_list:
            if auth_record_object.system == inc_system:
                if inc_username:
                    auth_record_object.username = inc_username
                if inc_password:
                    auth_record_object.encrypt_password(inc_password)
                found = True

        if found:
            lg.info('Successfully edited the %s entry in %s.', inc_system, self.password_file_path)
            self.save_file()
        else:
            lg.warning('Could not find an entry with the system %s!', inc_system)

    def list_records(self):
        if self.gui_mode:
            lg.info('\nThese systems have a record in %s:', self.password_file_path)
            for auth_record_object in self.auth_records_list:
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
