class AdminSetupDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)

        self.setWindowTitle("Admin Account Setup")

        layout = QVBoxLayout()

        self.username_label = QLabel("Admin Username: Administrator")
        self.password_label = QLabel("Admin Password:")
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.username_label)
        layout.addWidget(self.password_label)
        layout.addWidget(self.password_input)

        self.password_confirmation_label = QLabel("Confirm Password:")
        self.password_confirmation_input = QLineEdit(self)
        self.password_confirmation_input.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.password_confirmation_label)
        layout.addWidget(self.password_confirmation_input)

        self.create_button = QPushButton("Create Admin Account")
        self.create_button.clicked.connect(self.accept)
        layout.addWidget(self.create_button)

        self.setLayout(layout)

    def accept(self):
        if self.password_input.text() == self.password_confirmation_input.text():
            super().accept()
        else:
            QMessageBox.warning(self, "Password Mismatch", "The passwords do not match. Please try again.")

def create_admin_account(connection):
    cursor = connection.cursor()
    
    # Check if "Owner" role exists, if not, create it
    cursor.execute("SELECT COUNT(*) FROM user_roles WHERE role_name = 'Owner'")
    if cursor.fetchone()[0] == 0:
        cursor.execute("INSERT INTO user_roles (role_name) VALUES ('Owner')")
        connection.commit()
    
    # Get the role_id of the "Owner" role
    cursor.execute("SELECT id FROM user_roles WHERE role_name = 'Owner'")
    owner_role_id = cursor.fetchone()[0]
    
    # Check if "Administrator" user exists, if not, create it
    cursor.execute("SELECT COUNT(*) FROM users WHERE username = 'Administrator'")
    if cursor.fetchone()[0] == 0:
        admin_setup_dialog = AdminSetupDialog()
        result = admin_setup_dialog.exec()

        if result == QDialog.DialogCode.Accepted:
            admin_password = admin_setup_dialog.password_input.text()
            admin_password_hash = hash_password(admin_password)
            cursor.execute(
                "INSERT INTO users (username, password_hash, role_id) VALUES ('Administrator', %s, %s)",
                (admin_password_hash, owner_role_id)
            )
            connection.commit()
            print("Admin account created successfully.")
    else:
        print("Admin account already exists.")

class UsersDialog(QDialog):
    def __init__(self, connection, parent=None):
        super().__init__(parent)
        self.connection = connection
        self.setWindowTitle("Manage Users")

        # Layouts
        self.main_layout = QVBoxLayout(self)
        self.form_layout = QGridLayout()

        # Widgets
        self.user_list = QListWidget()
        self.add_user_button = QPushButton("Add User")
        self.edit_user_button = QPushButton("Edit User")
        self.delete_user_button = QPushButton("Delete User")

        # Adding widgets to form layout
        self.form_layout.addWidget(self.add_user_button, 1, 0)
        self.form_layout.addWidget(self.edit_user_button, 1, 1)
        self.form_layout.addWidget(self.delete_user_button, 2, 0)

        # Adding layouts and widgets to main layout
        self.main_layout.addWidget(self.user_list)
        self.main_layout.addLayout(self.form_layout)

        # Connect the buttons to the corresponding methods
        self.add_user_button.clicked.connect(self.add_user)
        self.edit_user_button.clicked.connect(self.edit_user)
        self.delete_user_button.clicked.connect(self.delete_user)

        # Load users into the list
        self.load_users()

    def load_users(self):
        # Load users from the database and add them to the QListWidget
        query = "SELECT * FROM users"
        users = execute_query(self.connection, query)  # Use self.connection here
        self.user_list.clear()

        for user in users:
            self.user_list.addItem(f"{user[0]} - {user[1]} - {user[2]}")  # Assuming the users table has id, username, and role_id columns
            
    def add_user(self):
        dialog = UserCreationDialog(self.connection, self)
        result = dialog.exec()

        if result == QDialog.DialogCode.Accepted:
            username = dialog.username_input.text()
            password = dialog.password_input.text()
            role_name = dialog.role_combo.currentText()
            role_id = dialog.role_mapping[role_name]

            if username and is_password_complex(password):
                # Check if the role is 'owner' or the username is 'Administrator'
                cursor = self.connection.cursor()
                if role_name == 'owner':
                    cursor.execute("SELECT is_owner_role_assignable FROM user_roles WHERE role_name = 'owner'")
                    is_owner_role_assignable = cursor.fetchone()[0]
                    if not is_owner_role_assignable:
                        QMessageBox.warning(self, "Error", "The owner role has already been assigned.")
                        return
                    cursor.execute("UPDATE user_roles SET is_owner_role_assignable = False WHERE role_name = 'owner'")
                if username == 'Administrator':
                    cursor.execute("SELECT is_admin_created FROM users WHERE username = 'Administrator'")
                    is_admin_created = cursor.fetchone()[0]
                    if is_admin_created:
                        QMessageBox.warning(self, "Error", "The Administrator account has already been created.")
                        return
                    cursor.execute("UPDATE users SET is_admin_created = True WHERE username = 'Administrator'")
                password_hash = hash_password(password)
                query = f"INSERT INTO users (username, password_hash, role_id) VALUES ('{username}', '{password_hash}', '{role_id}')"
                execute_query(self.connection, query)
                self.load_users()
            else:
                QMessageBox.warning(self, "Error", "Please fill in all fields and make sure password is complex.") 

    def edit_user(self):
        # Edit the selected user
        # You can use the EditUserDialog here
        selected_item = self.user_list.currentItem()

        if selected_item:
            user_id, username, _ = selected_item.text().split(" - ")
            dialog = EditUserDialog(user_id, username, self.connection, self)
            result = dialog.exec()

            if result == QDialog.DialogCode.Accepted:

                self.load_users()
        else:
            QMessageBox.warning(self, "Error", "Please select a user to edit.")

    def delete_user(self):
        # Delete the selected user from the database
        selected_item = self.user_list.currentItem()

        if selected_item:
            user_id, username, _ = selected_item.text().split(" - ")

            # Check if the user is an admin
            cursor = self.connection.cursor()
            cursor.execute("SELECT role_id FROM users WHERE id = %s", (user_id,))
            role_id = cursor.fetchone()[0]
            cursor.execute("SELECT role_name FROM user_roles WHERE id = %s", (role_id,))
            role_name = cursor.fetchone()[0]

            if role_name == "admin":
                QMessageBox.warning(self, "Error", "The administrator account cannot be deleted.")
                return

            confirm = QMessageBox.question(self, "Delete User", "Are you sure you want to delete the selected user?",
                                           QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)

            if confirm == QMessageBox.StandardButton.Yes:
                if username == "Administrator":
                    cursor.execute("UPDATE users SET is_admin_created = False WHERE username = 'Administrator'")
                query = f"DELETE FROM users WHERE id={user_id}"
                execute_query(self.connection, query)
                self.load_users()
        else:
            QMessageBox.warning(self, "Error", "Please select a user to delete.")

class UserCreationDialog(QDialog):
    def __init__(self, connection, parent=None):
        super().__init__(parent)
        self.connection = connection
        self.setWindowTitle("Create User")

        # Layout
        layout = QVBoxLayout(self)

        # Widgets
        self.username_label = QLabel("Username:")
        self.username_input = QLineEdit()
        self.password_label = QLabel("Password:")
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.confirm_password_label = QLabel("Confirm Password:")
        self.confirm_password_input = QLineEdit()
        self.confirm_password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.role_label = QLabel("Role:")
        self.role_combo = QComboBox()

        # Load roles into the combobox
        self.role_mapping = self.load_roles()

        self.create_button = QPushButton("Create User")
        self.create_button.clicked.connect(self.accept)

        # Adding widgets to the layout
        layout.addWidget(self.username_label)
        layout.addWidget(self.username_input)
        layout.addWidget(self.password_label)
        layout.addWidget(self.password_input)
        layout.addWidget(self.confirm_password_label)
        layout.addWidget(self.confirm_password_input)
        layout.addWidget(self.role_label)
        layout.addWidget(self.role_combo)
        layout.addWidget(self.create_button)

        self.setLayout(layout)

    def load_roles(self):
        query = "SELECT id, role_name FROM user_roles"
        roles = execute_query(self.connection, query)
        role_mapping = {}
        for role_id, role_name in roles:
            self.role_combo.addItem(role_name)
            role_mapping[role_name] = role_id
        return role_mapping

    def accept(self):
        username = self.username_input.text()
        password = self.password_input.text()
        confirm_password = self.confirm_password_input.text()
        role_name = self.role_combo.currentText()

        if username and password and confirm_password and role_name:
            if password == confirm_password:
                if is_password_complex(password):
                    super().accept()
                else:
                    QMessageBox.warning(self, "Input Error", "Please ensure the password is complex.")
            else:
                QMessageBox.warning(self, "Input Error", "Passwords do not match.")
        else:
            QMessageBox.warning(self, "Input Error", "Please fill in all fields.")

class EditUserDialog(QDialog):
    def __init__(self, user_id, username, connection, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"Edit User: {username}")
        self.user_id = user_id
        self.connection = connection

        # Layouts
        self.main_layout = QVBoxLayout(self)
        self.buttons_layout = QHBoxLayout()

        # Widgets
        self.username_input = QLineEdit()
        self.username_input.setText(username)
        self.change_password_button = QPushButton("Change Password")
        self.change_role_button = QPushButton("Change Role")

        # Adding widgets to buttons layout
        self.buttons_layout.addWidget(self.change_password_button)
        self.buttons_layout.addWidget(self.change_role_button)

        # Adding layouts and widgets to main layout
        self.main_layout.addWidget(self.username_input)
        self.main_layout.addLayout(self.buttons_layout)

        # Connect the buttons to the corresponding methods
        self.change_password_button.clicked.connect(self.change_password)
        self.change_role_button.clicked.connect(self.change_role)

    def change_password(self):
        dialog = ChangePasswordDialog(self)
        result = dialog.exec()

        if result == QDialog.DialogCode.Accepted:
            new_password, confirm_password = dialog.get_values()

            if new_password and confirm_password and new_password == confirm_password and is_password_complex(new_password):
                password_hash = hash_password(new_password)
                query = f"UPDATE users SET password_hash='{password_hash}' WHERE id={self.user_id}"
                execute_query(self.connection, query)
            else:
                QMessageBox.warning(self, "Error", "Passwords do not match, are not complex enough, or are empty. Please try again.")

    def change_role(self):
        # Show a dialog to select the new role
        query = "SELECT role_name FROM user_roles"
        roles = execute_query(self.parent().connection, query)
        role_names = [role[0] for role in roles]

        new_role, ok = QInputDialog.getItem(self, "Change Role", "Select a new role:", role_names, 0, False)

        if ok and new_role:
            if new_role == "owner":
                cursor = self.parent().connection.cursor()

class ChangePasswordDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)

        self.setWindowTitle("Change Password")

        self.main_layout = QVBoxLayout(self)

        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)

        self.confirm_password_input = QLineEdit()
        self.confirm_password_input.setEchoMode(QLineEdit.EchoMode.Password)

        self.submit_button = QPushButton("Submit")

        self.main_layout.addWidget(QLabel("New Password:"))
        self.main_layout.addWidget(self.password_input)
        self.main_layout.addWidget(QLabel("Confirm New Password:"))
        self.main_layout.addWidget(self.confirm_password_input)
        self.main_layout.addWidget(self.submit_button)

        self.submit_button.clicked.connect(self.submit)

    def submit(self):
        password = self.password_input.text()
        confirm_password = self.confirm_password_input.text()

        if password and password == confirm_password and is_password_complex(password):
            self.accept()
        else:
            QMessageBox.warning(self, "Error", "Passwords do not match or password not complex enough.")

    def get_values(self):
        return self.password_input.text(), self.confirm_password_input.text()

class UserGroupsDialog(QDialog):
    OWNER_ROLE_ID = 1  # assuming owner role id is 1, adjust according to your data

    def __init__(self, connection, parent=None):
        super().__init__(parent)
        self.connection = connection
        self.setWindowTitle("Manage User Groups")

        # Layouts
        self.main_layout = QVBoxLayout(self)
        self.form_layout = QGridLayout()

        # Widgets
        self.group_list = QListWidget()
        self.add_group_button = QPushButton("Add Group")
        self.edit_group_button = QPushButton("Edit Group")
        self.delete_group_button = QPushButton("Delete Group")

        # Adding widgets to form layout
        self.form_layout.addWidget(self.add_group_button, 1, 0)
        self.form_layout.addWidget(self.edit_group_button, 1, 1)
        self.form_layout.addWidget(self.delete_group_button, 2, 0)

        # Adding layouts and widgets to main layout
        self.main_layout.addWidget(self.group_list)
        self.main_layout.addLayout(self.form_layout)

        # Connect the buttons to the corresponding methods
        self.add_group_button.clicked.connect(self.add_group)
        self.edit_group_button.clicked.connect(self.edit_group)
        self.delete_group_button.clicked.connect(self.delete_group)

        # Load groups into the list
        self.load_groups()

    # Add a new method for the "Rename Group" button
    def rename_group(self):
        selected_item = self.group_list.currentItem()

        if selected_item:
            group_id, group_name = selected_item.text().split(" - ")
            new_group_name, ok = QInputDialog.getText(self, "Rename Group", "Enter a new group name:", text=group_name)

            if ok and new_group_name.strip():
                query = f"UPDATE user_roles SET role_name='{new_group_name.strip()}' WHERE id={group_id}"
                execute_query(self.parent().connection, query)
                self.load_groups()
            elif ok:
                QMessageBox.warning(self, "Error", "Please enter a group name.")
        else:
            QMessageBox.warning(self, "Error", "Please select a group to rename.")

    def load_groups(self):
        query = "SELECT * FROM user_roles WHERE id != " + str(self.OWNER_ROLE_ID)
        groups = execute_query(self.parent().connection, query)
        self.group_list.clear()

        for group in groups:
            self.group_list.addItem(f"{group[0]} - {group[1]}")

    def add_group(self):
        # Add a new user group to the database
        group_name = self.group_name_input.text().strip()

        if group_name:
            query = f"INSERT INTO user_roles (role_name) VALUES ('{group_name}')"
            execute_query(self.parent().connection, query)
            self.load_groups()
            self.group_name_input.clear()
        else:
            QMessageBox.warning(self, "Error", "Please enter a group name.")

    def edit_group(self):
        selected_item = self.group_list.currentItem()

        if selected_item:
            group_id, group_name = selected_item.text().split(" - ")

            if int(group_id) == self.OWNER_ROLE_ID:
                QMessageBox.warning(self, "Error", "The 'owner' role cannot be edited.")
                return

            new_group_name, ok = QInputDialog.getText(self, "Edit Group", "Enter a new group name:", text=group_name)

            if ok and new_group_name.strip():
                query = f"UPDATE user_roles SET role_name='{new_group_name.strip()}' WHERE id={group_id}"
                execute_query(self.connection, query)
                self.load_groups()
            elif ok:
                QMessageBox.warning(self, "Error", "Please enter a group name.")
        else:
            QMessageBox.warning(self, "Error", "Please select a group to edit.")

    def delete_group(self):
        # Delete the selected user group from the database
        selected_item = self.group_list.currentItem()

        if selected_item:
            group_id, group_name = selected_item.text().split(" - ")

            if int(group_id) == self.OWNER_ROLE_ID:
                QMessageBox.warning(self, "Error", "The 'owner' role cannot be deleted.")
                return

            # Check if there are any users associated with this role
            check_query = f"SELECT COUNT(*) FROM users WHERE role_id={group_id}"
            result = execute_query(self.connection, check_query)
            user_count = result[0][0]

            if user_count > 0:
                QMessageBox.warning(self, "Error", "There are users associated with this role. Reassign or delete the users before deleting the role.")
                return

            if group_name != "Administrators":
                confirm = QMessageBox.question(self, "Delete Group", "Are you sure you want to delete the selected group?",
                                               QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)

                if confirm == QMessageBox.StandardButton.Yes:
                    query = f"DELETE FROM user_roles WHERE id={group_id}"
                    execute_query(self.connection, query)
                    self.load_groups()
            else:
                QMessageBox.warning(self, "Error", "Cannot delete 'Administrators' group.")
        else:
            QMessageBox.warning(self, "Error", "Please select a group to delete.")

class EditUserGroupDialog(QDialog):
    def __init__(self, group_id, group_name, connection, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"Edit Group: {group_name}")
        self.group_id = group_id
        self.connection = connection

        # Layouts
        self.main_layout = QVBoxLayout(self)
        self.buttons_layout = QHBoxLayout()

        # Widgets
        self.user_list = QListWidget()
        self.add_user_button = QPushButton("Add User")
        self.remove_user_button = QPushButton("Remove User")

        # Adding widgets to buttons layout
        self.buttons_layout.addWidget(self.add_user_button)
        self.buttons_layout.addWidget(self.remove_user_button)

        # Adding layouts and widgets to main layout
        self.main_layout.addWidget(self.user_list)
        self.main_layout.addLayout(self.buttons_layout)

        # Connect the buttons to the corresponding methods
        self.add_user_button.clicked.connect(self.add_user_to_group)
        self.remove_user_button.clicked.connect(self.remove_user_from_group)

        self.load_users()

    def load_users(self):
        query = f"SELECT users.id, users.username FROM users WHERE users.role_id = {self.group_id}"
        users = execute_query(self.connection, query)
        self.user_list.clear()

        for user in users:
            self.user_list.addItem(f"{user[0]} - {user[1]}")

    def add_user_to_group(self):
        # Show a dialog with a list of users not in the group
        not_in_group_users = self.get_users_not_in_group()
        not_in_group_dialog = QDialog(self)
        not_in_group_dialog.setWindowTitle("Add User")
        not_in_group_dialog.setLayout(QVBoxLayout())

        user_list = QListWidget()
        for user in not_in_group_users:
            user_list.addItem(f"{user[0]} - {user[1]}")
        not_in_group_dialog.layout().addWidget(user_list)

        add_button = QPushButton("Add User to Group")
        not_in_group_dialog.layout().addWidget(add_button)

        add_button.clicked.connect(not_in_group_dialog.accept)
        result = not_in_group_dialog.exec()

        if result == QDialog.DialogCode.Accepted:

            selected_user = user_list.currentItem()
            if selected_user:
                user_id, _ = selected_user.text().split(" - ")
                query = f"UPDATE users SET role_id={self.group_id} WHERE id={user_id}"
                execute_query(self.parent().connection, query)
                self.load_users()

    def remove_user_from_group(self):
        selected_user = self.user_list.currentItem()
        if selected_user:
            user_id, _ = selected_user.text().split(" - ")
            query = f"UPDATE users SET role_id=NULL WHERE id={user_id}"
            execute_query(self.parent().connection, query)
            self.load_users()

    def get_users_not_in_group(self):
        query = f"SELECT id, username FROM users WHERE role_id != {self.group_id} OR role_id IS NULL"
        users = execute_query(self.parent().connection, query)
        return users

class Permissions:
    def __init__(self, connection):
        self.connection = connection

    def load_user_permissions(self, user_id=None, group_id=None):
        if user_id is None and group_id is None:
            raise ValueError("Either user_id or group_id must be provided")

        if user_id is not None:
            query = "SELECT permission FROM permissions WHERE user_id = ?"
            values = (user_id,)
        else:
            query = "SELECT permission FROM permissions WHERE group_id = ?"
            values = (group_id,)

        cursor = self.connection.cursor()
        cursor.execute(query, values)
        permissions = cursor.fetchall()

        if permissions is not None:
            permissions_list = [permission[0] for permission in permissions]
            return permissions_list
        else:
            return []

    def has_permission(self, user_id=None, group_id=None, permission=None):
        if user_id is not None:
            query = f"SELECT permission FROM permissions WHERE user_id = ? AND permission = ?"
            values = (user_id, permission)
        elif group_id is not None:
            query = f"SELECT permission FROM permissions WHERE group_id = ? AND permission = ?"
            values = (group_id, permission)
        else:
            raise ValueError("Either user_id or group_id must be provided")

        cursor = self.connection.cursor()
        cursor.execute(query, values)
        result = cursor.fetchone()

        return result is not None

    def add_permission(self, user_id=None, group_id=None, permission=None):
        if user_id is not None:
            query = f"INSERT INTO permissions (user_id, permission) VALUES (?, ?)"
            values = (user_id, permission)
        elif group_id is not None:
            query = f"INSERT INTO permissions (group_id, permission) VALUES (?, ?)"
            values = (group_id, permission)
        else:
            raise ValueError("Either user_id or group_id must be provided")

        cursor = self.connection.cursor()
        cursor.execute(query, values)
        self.connection.commit()

    def remove_permission(self, user_id=None, group_id=None, permission=None):
        if user_id is not None:
            query = f"DELETE FROM permissions WHERE user_id = ? AND permission = ?"
            values = (user_id, permission)
        elif group_id is not None:
            query = f"DELETE FROM permissions WHERE group_id = ? AND permission = ?"
            values = (group_id, permission)
        else:
            raise ValueError("Either user_id or group_id must be provided")

        cursor = self.connection.cursor()
        cursor.execute(query, values)
        self.connection.commit()

