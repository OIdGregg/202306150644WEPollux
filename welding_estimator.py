import os
import traceback
import logging
import inspect
import subprocess
import pymysql
import shutil
import sys
import re
import mysql.connector
import pycountry
from datetime import datetime
from dotenv import load_dotenv
from PyQt6.QtWidgets import (QApplication, QMainWindow, QLabel, QLineEdit, QVBoxLayout, QHBoxLayout, QPushButton,
                             QTableWidget, QTableWidgetItem, QHeaderView, QFormLayout, QComboBox, QMenu, QDialog,
                             QDialogButtonBox, QMessageBox, QWidget, QSpinBox, QFrame, QSizePolicy, QAbstractItemView,
                             QMenuBar, QDoubleSpinBox, QGridLayout, QListWidget, QCheckBox, QInputDialog)
from PyQt6.QtGui import QIcon, QAction, QFont, QPalette, QColor
from PyQt6.QtCore import Qt, QSettings, pyqtSignal, pyqtSlot
from PyQt6.QtPrintSupport import QPrinter, QPrintDialog
from mysql.connector import Error
from passlib.hash import bcrypt

load_dotenv()

admin_username = os.getenv('ADMIN_USERNAME')
admin_password = os.getenv('ADMIN_PASSWORD')
unit_system = os.getenv('UNIT_SYSTEM')

APP_VERSION = '1.0.0'

app = QApplication([])

# Replace these with your MySQL server credentials
host = "localhost"
user = "estimator"
password = "P0llux2023!"

# Name of the new database you want to create
new_database = "estimatordatabase"

# Connect to the MySQL server
connection = mysql.connector.connect(
    host=host,
    user=user,
    password=password
)

# Create a cursor object to execute SQL commands
cursor = connection.cursor()

# Check if the database already exists
cursor.execute(f"SHOW DATABASES LIKE '{new_database}'")
result = cursor.fetchone()

# If the database does not exist, create it
if not result:
    cursor.execute(f"CREATE DATABASE {new_database}")
    print(f"Database '{new_database}' created successfully.")
else:
    print(f"Database '{new_database}' already exists.")

# Close the cursor and the connection
cursor.close()
connection.close()

def setup_logging():
    logger = logging.getLogger("app")
    logger.setLevel(logging.DEBUG)

    file_handler = logging.FileHandler("debug.log")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s: %(message)s", datefmt="%Y-%m-%d %H:%M:%S"))

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.DEBUG)
    console_handler.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s: %(message)s", datefmt="%Y-%m-%d %H:%M:%S"))

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger

logger = setup_logging()

def log(*args, level=logging.INFO):
    message = ' '.join(str(arg) for arg in args)
    logger.log(level, message)
    QApplication.processEvents()

def log_current_state():
    stack = inspect.stack()
    call_stack = []
    for frame_info in stack:
        call_info = f'{frame_info.function} in {frame_info.filename}:{frame_info.lineno}'
        call_stack.append(call_info)
    call_stack_str = '\n'.join(call_stack)
    log(f'''Current call stack:
{call_stack_str}''')
    logging.error(f'''Current call stack:
{call_stack_str}''')

def check_log_directory():
    log_directory = 'logs'
    if (not os.path.exists(log_directory)):
        os.makedirs(log_directory)

def create_log_file():
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    log_filename = f'logs/welding_estimator_error_{timestamp}.log'
    return log_filename
log_filename = create_log_file()
logging.basicConfig(filename=log_filename, level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')

def handle_uncaught_exception(exc_type, exc_value, exc_traceback):
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
        return

    tb = ''.join(traceback.format_exception(exc_type, exc_value, exc_traceback))
    log('Error:', str(tb), level=logging.ERROR)
    logging.error('Uncaught exception', exc_info=(exc_type, exc_value, exc_traceback))
    log_current_state()
sys.excepthook = handle_uncaught_exception

def hash_password(password):
    return bcrypt.using(rounds=12).hash(password)

def verify_password(password, password_hash):
    return bcrypt.verify(password, password_hash)

def check_first_run():
    connection = create_database_connection()
    cursor = connection.cursor()
    cursor.execute('SELECT COUNT(*) FROM settings')
    row_count = cursor.fetchone()[0]
    cursor.close()
    connection.close()
    return (row_count == 0)

def is_password_complex(password):
    if len(password) < 8:
        return False
    if not re.search("[a-z]", password):
        return False
    if not re.search("[A-Z]", password):
        return False
    if not re.search("[0-9]", password):
        return False
    if not re.search("[!@#$%^&*]", password):
        return False
    return True

class MainWindow(QMainWindow):
    customer_added = pyqtSignal()

    def __init__(self, admin_username, admin_password_hash, unit_system):
        super().__init__()
        self.admin_username = admin_username
        self.admin_password_hash = admin_password_hash
        self.unit_system = unit_system
        self.setWindowTitle(f'Welding Estimator - v{APP_VERSION}')
        self.setWindowIcon(QIcon('icon.png'))
        self.app = QApplication.instance()
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        quotes_table_label = QLabel('Quotes:')
        self.quotes_table_label = quotes_table_label
        self.quotes_table = CustomTableWidget(0, 4)  # Change this line
        self.quotes_table.setObjectName("quotes_table")
        self.quotes_table.setHorizontalHeaderLabels(['Name', 'Client', 'Description', 'Date'])
        main_layout.addWidget(quotes_table_label)
        main_layout.addWidget(self.quotes_table)
        add_quote_button = QPushButton('Add Quote')
        add_quote_button.clicked.connect(self.add_quote)
        main_layout.addWidget(add_quote_button)
        self.customers_table_label = QLabel('Customers:')
        self.customers_table = CustomTableWidget(0, 4)  # Change this line
        self.customers_table.setObjectName("customers_table")
        self.customers_table.setHorizontalHeaderLabels(['Name', 'Alias', 'Description', 'Notes'])
        main_layout.addWidget(self.customers_table_label)
        main_layout.addWidget(self.customers_table)
        self.customers_table_label.hide()
        self.customers_table.hide()
        self.add_quote_button = add_quote_button

        add_customer_button = QPushButton('Add Customer')
        add_customer_button.clicked.connect(self.add_customer)
        main_layout.addWidget(add_customer_button)
        add_customer_button.hide()
        self.add_customer_button = add_customer_button

        # Parts section
        parts_table_label = QLabel('Parts:')
        self.parts_table_label = parts_table_label
        self.parts_table = CustomTableWidget(0, 10)  # Change this line
        self.parts_table.setObjectName("parts_table")
        self.parts_table.setHorizontalHeaderLabels(['Name', 'Part #', 'Description', 'Unit of Measurement', 'Weight', 'Width', 'Length', 'Area in²', 'Price Per in²', 'Price'])
        main_layout.addWidget(parts_table_label)
        main_layout.addWidget(self.parts_table)
        parts_table_label.hide()
        self.parts_table.hide()

        add_part_button = QPushButton('Add Part')
        add_part_button.clicked.connect(self.add_part)
        main_layout.addWidget(add_part_button)
        add_part_button.hide()
        self.add_part_button = add_part_button

        # Processes section
        processes_table_label = QLabel('Processes:')
        self.processes_table_label = processes_table_label
        self.processes_table = CustomTableWidget(0, 4)
        self.processes_table.setObjectName("processes_table")
        self.processes_table.setHorizontalHeaderLabels(['Name', 'Price', 'Units of Measurement', 'Notes'])
        main_layout.addWidget(processes_table_label)
        main_layout.addWidget(self.processes_table)
        processes_table_label.hide()
        self.processes_table.hide()

        add_process_button = QPushButton('Add Process')
        add_process_button.clicked.connect(self.add_process)  # Add this line
        main_layout.addWidget(add_process_button)
        add_process_button.hide()
        self.add_process_button = add_process_button

        self.permissions = Permissions(self.connection)

        self.init_menu_bar()

        # Call show_quotes to display quotes on the main screen
        self.show_quotes()

    def create_connection(host_name, user_name, user_password, db_name=None):
        connection = None
        try:
            connection = mysql.connector.connect(
                host=host_name,
                user=user_name,
                passwd=user_password
            )
            cursor = connection.cursor()

            if db_name:
                cursor.execute(f"SHOW DATABASES LIKE '{db_name}'")
                result = cursor.fetchone()
                if not result:
                    cursor.execute(f"CREATE DATABASE {db_name}")
                    print(f"Database '{db_name}' created successfully.")
                else:
                    print(f"Database '{db_name}' already exists.")
                connection.database = db_name
            print("Connection to MySQL DB successful")

        except Error as e:
            print(f"The error '{e}' occurred")

        return connection

    # Replace with your MySQL credentials and database name
    host = "localhost"
    user = "estimator"
    password = "P0llux2023!"
    database = "estimatordatabase"

    connection = create_connection(host, user, password, database)

    # Create tables
    create_parts_table = """
    CREATE TABLE IF NOT EXISTS parts (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        manufacturer VARCHAR(255) NOT NULL
    );
    """

    create_suppliers_table = """
    CREATE TABLE IF NOT EXISTS suppliers (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        contact_name VARCHAR(255) NOT NULL,
        phone VARCHAR(255) NOT NULL,
        email VARCHAR(255) NOT NULL
    );
    """

    create_inventory_table = """
    CREATE TABLE IF NOT EXISTS inventory (
        id INT AUTO_INCREMENT PRIMARY KEY,
        part_id INT,
        supplier_id INT,
        quantity INT NOT NULL,
        FOREIGN KEY (part_id) REFERENCES parts (id),
        FOREIGN KEY (supplier_id) REFERENCES suppliers (id)
    );
    """

    create_user_groups_table = """
    CREATE TABLE IF NOT EXISTS user_groups (
        id INT AUTO_INCREMENT PRIMARY KEY,
        group_name VARCHAR(255) NOT NULL UNIQUE
    );
    """

    create_group_permissions_table = """
    CREATE TABLE IF NOT EXISTS group_permissions (
        id INT AUTO_INCREMENT PRIMARY KEY,
        group_id INT,
        permission_name VARCHAR(255) NOT NULL,
        FOREIGN KEY (group_id) REFERENCES user_groups(id)
    );
    """

    create_users_table = """
    CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(255) NOT NULL UNIQUE,
        password_hash VARCHAR(255) NOT NULL,
        group_id INT,
        FOREIGN KEY (group_id) REFERENCES user_groups(id)
    );
    """

    # Execute the queries to create the new tables and update the users table
    execute_query(connection, create_user_groups_table)
    execute_query(connection, create_group_permissions_table)
    execute_query(connection, create_users_table)

    # Check and create admin account if it doesn't exist
    create_admin_account(connection)

    def init_menu_bar(self):
        self.menu_bar = QMenuBar(self)

        file_menu = self.menu_bar.addMenu('File')

        settings_action = QAction('Settings', self)
        file_menu.addAction(settings_action)

        file_menu.addSeparator()

        exit_action = QAction('Exit', self)
        exit_action.setShortcut('Ctrl+Q')
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        view_menu = self.menu_bar.addMenu('View')

        view_quotes_action = QAction('View Quotes', self)
        view_quotes_action.triggered.connect(self.show_quotes)
        view_menu.addAction(view_quotes_action)

        view_customers_action = QAction('View Customers', self)
        view_customers_action.triggered.connect(self.show_customers)
        view_menu.addAction(view_customers_action)

        view_parts_action = QAction('View Parts', self)
        view_parts_action.triggered.connect(self.show_parts)
        view_menu.addAction(view_parts_action)

        view_processes_action = QAction('View Processes', self)
        view_processes_action.triggered.connect(self.show_processes)
        view_menu.addAction(view_processes_action)

        self.user_management_menu = self.menu_bar.addMenu("User Management")

        manage_users_action = QAction("Manage Users", self)
        manage_users_action.triggered.connect(self.show_users_dialog)
        self.user_management_menu.addAction(manage_users_action)

        manage_user_groups_action = QAction("Manage User Groups", self)
        manage_user_groups_action.triggered.connect(self.show_user_groups_dialog)
        self.user_management_menu.addAction(manage_user_groups_action)

        self.setMenuBar(self.menu_bar)

    def backup_database(self):
        try:
            # MySQL database credentials
            db_host = 'localhost'
            db_user = 'estimator'
            db_password = 'P0llux2023!'
            db_name = 'estimatordatabase'
            backup_directory = 'I:/Backup/Database'  # Change the backup directory to use forward slashes

            # Connect to the database
            connection = pymysql.connect(host=db_host, user=db_user, password=db_password, database=db_name)

            # Check if mysqldump is available
            try:
                subprocess.run(["mysqldump", "--version"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except subprocess.CalledProcessError:
                print("Error: mysqldump not found. Please ensure it's installed and in the system PATH.")
                connection.close()
                return

            # Generate a timestamp
            timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

            # Use mysqldump to create a backup file
            backup_file = os.path.join(backup_directory, f"{db_name}_backup_{timestamp}.sql")
            with open(backup_file, 'wb') as f:
                subprocess.call(['mysqldump', f'--user={db_user}', f'--password={db_password}', db_name], stdout=f)

            # Verify the backup file exists
            if os.path.exists(backup_file):
                print(f"Backup created: {backup_file}")
            else:
                print("Backup failed: backup file not found")

            # Close the database connection
            connection.close()

        except Exception as e:
            # Handle any errors that occur during the backup process
            print(f"Error during backup: {e}")

    def view_entry(self, entry_id):
        # Fetch entry details from the database using entry_id
        entry_details = self.get_entry_details(entry_id)

        # Create a QDialog to display entry details
        view_dialog = QDialog(self)
        view_dialog.setWindowTitle('View Entry')
        view_dialog.setModal(True)

        layout = QVBoxLayout(view_dialog)

        # Display entry details in read-only QLineEdit widgets
        for key, value in entry_details.items():
            key_label = QLabel(key.capitalize() + ':')
            value_line_edit = QLineEdit(value)
            value_line_edit.setReadOnly(True)
            layout.addWidget(key_label)
            layout.addWidget(value_line_edit)

        # Display statistical information
        created_label = QLabel(f"Created: {entry_details['created']}")
        edited_label = QLabel(f"Last Edited: {entry_details['last_edited']}")
        edited_by_label = QLabel(f"Edited by: {entry_details['edited_by']}")
        layout.addWidget(created_label)
        layout.addWidget(edited_label)
        layout.addWidget(edited_by_label)

        # Add Close button
        close_button = QPushButton('Close')
        close_button.clicked.connect(view_dialog.close)
        layout.addWidget(close_button)

        view_dialog.setLayout(layout)
        view_dialog.exec()

    def get_entry_details(self, entry_id):
        # Fetch entry details from the database using entry_id and return a dictionary
        pass

    def get_quotes(self):
        # Fetch quotes from the database and return a list of tuples
        # Return an empty list if no quotes are found
        quotes = []  # Replace with actual code to fetch quotes from the database
        return quotes

    def show_quotes(self):
        self.setWindowTitle(f'Welding Estimator - v{APP_VERSION} - Quotes')
        self.quotes_table_label.show()
        self.quotes_table.show()
        self.add_quote_button.show()

        self.customers_table_label.hide()
        self.customers_table.hide()
        self.add_customer_button.hide()

        self.parts_table_label.hide()
        self.parts_table.hide()
        self.add_part_button.hide()

        # Hide Processes section
        self.processes_table_label.hide()
        self.processes_table.hide()
        self.add_process_button.hide()

        self.quotes_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.quotes_table.setSortingEnabled(True)

    def show_customers(self):
        self.setWindowTitle(f'Welding Estimator - v{APP_VERSION} - Customers')
        self.quotes_table_label.hide()
        self.quotes_table.hide()
        self.add_quote_button.hide()

        self.customers_table_label.show()
        self.customers_table.show()
        self.add_customer_button.show()

        self.parts_table_label.hide()
        self.parts_table.hide()
        self.add_part_button.hide()

        # Hide Processes section
        self.processes_table_label.hide()
        self.processes_table.hide()
        self.add_process_button.hide()

    def show_parts(self):
        self.setWindowTitle(f'Welding Estimator - v{APP_VERSION} - Parts')
        self.quotes_table_label.hide()
        self.quotes_table.hide()
        self.add_quote_button.hide()

        self.customers_table_label.hide()
        self.customers_table.hide()
        self.add_customer_button.hide()

        self.parts_table_label.show()
        self.parts_table.show()
        self.add_part_button.show()

        # Hide Processes section
        self.processes_table_label.hide()
        self.processes_table.hide()
        self.add_process_button.hide()

    def show_processes(self):
        self.setWindowTitle(f'Welding Estimator - v{APP_VERSION} - Processes')
        # Hide other sections
        self.quotes_table_label.hide()
        self.quotes_table.hide()
        self.add_quote_button.hide()
        self.customers_table_label.hide()
        self.customers_table.hide()
        self.add_customer_button.hide()
        self.parts_table_label.hide()
        self.parts_table.hide()
        self.add_part_button.hide()

        # Show Processes section
        self.processes_table_label.show()
        self.processes_table.show()
        self.add_process_button.show()

        self.processes_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.processes_table.setSortingEnabled(True)

    def show_user_creation_dialog(self):
        user_creation_dialog = UserCreationDialog(self)
        result = user_creation_dialog.exec()

        if result == QDialog.DialogCode.Accepted:
            username = user_creation_dialog.username_input.text()
            password = user_creation_dialog.password_input.text()
            role = user_creation_dialog.role_combo.currentText()

            # You can add the code to insert the new user into the database here
            print(f"Creating user '{username}' with role '{role}'")

    def show_user_groups_dialog(self):
        user_groups_dialog = UserGroupsDialog(self.connection, self)
        result = user_groups_dialog.exec()

        if result == QDialog.DialogCode.Accepted:
            # Handle user group changes if needed
            self.update_user_groups_dependents()

    def show_users_dialog(self):
        print("Opening user management dialog...")
        users_dialog = UsersDialog(self.connection, self)
        users_dialog.exec()
           
    def add_quote(self):
        add_quote_dialog = QDialog(self)
        add_quote_dialog.setWindowTitle('Add Quote')
        add_quote_dialog.setModal(True)

        layout = QVBoxLayout(add_quote_dialog)

        quote_name_label = QLabel('Quote Name:')
        quote_name_edit = QLineEdit()
        layout.addWidget(quote_name_label)
        layout.addWidget(quote_name_edit)

        customer_label = QLabel('Customer:')
        customer_combo = QComboBox()
        customers = self.get_customers()
        for customer in customers:
            customer_combo.addItem(customer)
        customer_combo.addItem('Add new customer...')
        customer_combo.currentIndexChanged.connect(lambda idx: self.add_new_customer(idx, customer_combo))
        layout.addWidget(customer_label)
        layout.addWidget(customer_combo)

        save_button = QPushButton('Save')
        save_button.clicked.connect(lambda: self.save_quote(quote_name_edit.text(), customer_combo.currentText(), add_quote_dialog))
        layout.addWidget(save_button)

        add_quote_dialog.setLayout(layout)
        add_quote_dialog.exec()

    def add_customer(self):  # Ensure this function is present in the MainWindow class
        add_customer_dialog = AddCustomerDialog(self)
        result = add_customer_dialog.exec()

        if result == QDialog.DialogCode.Accepted:
            alias = add_customer_dialog.alias_edit.text()
            name = add_customer_dialog.name_edit.text()
            description = add_customer_dialog.description_edit.text()
            notes = add_customer_dialog.notes_edit.text()
            address1 = add_customer_dialog.address1_edit.text()
            address2 = add_customer_dialog.address2_edit.text()
            city = add_customer_dialog.city_edit.text()
            state = add_customer_dialog.state_combo.currentText()
            zip_code = add_customer_dialog.zip_edit.text()
            country = add_customer_dialog.country_combo.currentText()

            row_position = self.customers_table.rowCount()
            self.customers_table.insertRow(row_position)
            self.customers_table.setItem(row_position, 0, QTableWidgetItem(name))
            self.customers_table.setItem(row_position, 1, QTableWidgetItem(alias))
            self.customers_table.setItem(row_position, 2, QTableWidgetItem(description))
            self.customers_table.setItem(row_position, 3, QTableWidgetItem(notes))

            # Emit the customer_added signal after adding the new customer
            self.customer_added.emit()

    def add_process(self):
        add_process_dialog = AddProcessDialog(self)
        result = add_process_dialog.exec()

        if result == QDialog.DialogCode.Accepted:
            process_data = add_process_dialog.get_data()

            row = self.processes_table.rowCount()
            self.processes_table.insertRow(row)

            for column, data in enumerate(process_data):
                if column == 1:
                    item = QTableWidgetItem("${:,.2f}".format(float(data.replace('$', ''))))
                else:
                    item = QTableWidgetItem(str(data))
                self.processes_table.setItem(row, column, item)
            
    @pyqtSlot()
    def update_customer_list(self):
        customers = self.get_customers()
        self.customer_combo.clear()
        for customer in customers:
            self.customer_combo.addItem(customer)
        self.customer_combo.addItem('Add new customer...')

    def get_customers(self):
        # Fetch customers from the database and return a list of customer names
        # Return an empty list if no customers are found
        customers = []  # Replace with actual code to fetch customers from the database
        return customers

    def get_customers_from_table(self):
        customers = []
        for row in range(self.customers_table.rowCount()):
            customer_name = self.customers_table.item(row, 0).text()
            customers.append(customer_name)
        return customers

    def save_quote(self, quote_name, customer_name, dialog):
        if quote_name.strip() and customer_name.strip():
            # Save the quote to the database
            pass
            dialog.close()

    def add_part(self):
        add_part_dialog = AddPartDialog(self)
        result = add_part_dialog.exec()

        if result == QDialog.DialogCode.Accepted:
            part_data = add_part_dialog.get_data()

            row = self.parts_table.rowCount()
            self.parts_table.insertRow(row)

            # Calculate area in square inches
            area_in_sq_inches = float(part_data['width']) * float(part_data['length'])

            # Calculate price per square inch
            price_per_sq_inches = part_data['price'] / area_in_sq_inches

            data_to_display = [
                part_data['name'],
                part_data['part_number'],
                part_data['description'],
                part_data['unit_of_measurement'],
                part_data['weight'],
                part_data['width'],
                part_data['length'],
                f'{area_in_sq_inches:.2f}',  # Format with 2 decimal places
                f'{price_per_sq_inches:.2f}',  # Format with 2 decimal places
                f'{part_data["price"]:.2f}'  # Format with 2 decimal places
            ]


            for column, data in enumerate(data_to_display):
                if column in (8, 9):  # 'Price Per in²' and 'Price' columns
                    item = QTableWidgetItem(f"${data}")
                else:
                    item = QTableWidgetItem(str(data))
                self.parts_table.setItem(row, column, item)
    
    def open_parts(self):
        try:
            logging.info('Opening PartsWindow...')
            parts_window = PartsWindow(self)
            parts_window.exec()
        except Exception as e:
            logging.error(f'''Error occurred while opening PartsWindow:
{traceback.format_exc()}''')

    def refresh_user_permissions(self):
        # Assuming you have a current_user_id attribute set
        self.user_permissions = self.permissions.load_user_permissions(user_id=self.current_user_id)

    def check_permission(self, permission):
        return permission in self.user_permissions

    def closeEvent(self, event):
        log('Closing application...')
        # self.save_settings()  # Remove this line
        event.accept()



class AddCustomerDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)

        self.setWindowTitle("Add Customer")

        layout = QVBoxLayout()

        self.alias_label = QLabel("Alias")
        self.alias_edit = QLineEdit()
        layout.addWidget(self.alias_label)
        layout.addWidget(self.alias_edit)

        self.name_label = QLabel("Name")
        self.name_edit = QLineEdit()
        layout.addWidget(self.name_label)
        layout.addWidget(self.name_edit)

        self.description_label = QLabel("Description")
        self.description_edit = QLineEdit()
        layout.addWidget(self.description_label)
        layout.addWidget(self.description_edit)

        self.notes_label = QLabel("Notes")
        self.notes_edit = QLineEdit()
        layout.addWidget(self.notes_label)
        layout.addWidget(self.notes_edit)

        self.address1_label = QLabel("Address 1")
        self.address1_edit = QLineEdit()
        layout.addWidget(self.address1_label)
        layout.addWidget(self.address1_edit)

        self.address2_label = QLabel("Address 2")
        self.address2_edit = QLineEdit()
        layout.addWidget(self.address2_label)
        layout.addWidget(self.address2_edit)

        self.city_label = QLabel("City")
        self.city_edit = QLineEdit()
        layout.addWidget(self.city_label)
        layout.addWidget(self.city_edit)

        self.state_label = QLabel("State")
        self.state_combo = QComboBox()
        self.state_combo.addItems(get_us_states_and_territories())
        layout.addWidget(self.state_label)
        layout.addWidget(self.state_combo)

        self.zip_label = QLabel("Zip Code")
        self.zip_edit = QLineEdit()
        layout.addWidget(self.zip_label)
        layout.addWidget(self.zip_edit)

        self.country_label = QLabel("Country")
        self.country_combo = QComboBox()
        self.country_combo.addItems([country.name for country in get_sorted_countries()])
        layout.addWidget(self.country_label)
        layout.addWidget(self.country_combo)

        button_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel, parent=self)
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)

        self.setLayout(layout)

def add_customer(self):
    add_customer_dialog = AddCustomerDialog(self)
    result = add_customer_dialog.exec()

    if result == QDialog.DialogCode.Accepted:
        # Retrieve the entered customer data
        alias = add_customer_dialog.alias_edit.text()
        name = add_customer_dialog.name_edit.text()
        description = add_customer_dialog.description_edit.text()
        notes = add_customer_dialog.notes_edit.text()
        address1 = add_customer_dialog.address1_edit.text()
        address2 = add_customer_dialog.address2_edit.text()
        city = add_customer_dialog.city_edit.text()
        state = add_customer_dialog.state_combo.currentText()
        zip_code = add_customer_dialog.zip_edit.text()
        country = add_customer_dialog.country_combo.currentText()

        # Add the new customer to the customers table
        row_position = self.customers_table.rowCount()
        self.customers_table.insertRow(row_position)
        self.customers_table.setItem(row_position, 0, QTableWidgetItem(name))
        self.customers_table.setItem(row_position, 1, QTableWidgetItem(alias))
        self.customers_table.setItem(row_position, 2, QTableWidgetItem(description))
        self.customers_table.setItem(row_position, 3, QTableWidgetItem(notes))

        # Save the customer data to your data storage system (e.g.,
        # a database, a file, etc.). This part depends on your chosen
        # storage method.

        # For example, if you are using a database, you would insert the new
        # customer data into the corresponding table in the database.

        # If you are using a file, you would append the new customer data
        # to the file or update the file accordingly.

def get_sorted_countries():
    countries = sorted(list(pycountry.countries), key=lambda x: x.name)
    top_countries = ['United States', 'Mexico', 'Canada']
    sorted_countries = [c for c in countries if c.name in top_countries] + \
                       [c for c in countries if c.name not in top_countries]
    return sorted_countries

def get_us_states_and_territories():
    states_and_territories = [
        'Alabama', 'Alaska', 'Arizona', 'Arkansas', 'California', 'Colorado',
        'Connecticut', 'Delaware', 'Florida', 'Georgia', 'Hawaii', 'Idaho',
        'Illinois', 'Indiana', 'Iowa', 'Kansas', 'Kentucky', 'Louisiana',
        'Maine', 'Maryland', 'Massachusetts', 'Michigan', 'Minnesota',
        'Mississippi', 'Missouri', 'Montana', 'Nebraska', 'Nevada',
        'New Hampshire', 'New Jersey', 'New Mexico', 'New York',
        'North Carolina', 'North Dakota', 'Ohio', 'Oklahoma', 'Oregon',
        'Pennsylvania', 'Rhode Island', 'South Carolina', 'South Dakota',
        'Tennessee', 'Texas', 'Utah', 'Vermont', 'Virginia', 'Washington',
        'West Virginia', 'Wisconsin', 'Wyoming',
        'American Samoa', 'Guam', 'Northern Mariana Islands',
        'Puerto Rico', 'U.S. Virgin Islands',
        'Armed Forces Americas', 'Armed Forces Europe', 'Armed Forces Pacific'
    ]
    return states_and_territories

def main():
    sys.excepthook = handle_uncaught_exception
    app = QApplication(sys.argv)
    admin_username = os.getenv('ADMIN_USERNAME')
    admin_password = os.getenv('ADMIN_PASSWORD')
    unit_system = os.getenv('UNIT_SYSTEM')
    admin_password_hash = hash_password(admin_password)
    check_log_directory()
    create_log_file()
    first_run = check_first_run()
    log('First run:', first_run)

    main_window = MainWindow(admin_username, admin_password_hash, unit_system)
    main_window.show()
    app.aboutToQuit.connect(main_window.backup_database)  # Connect backup_database method to aboutToQuit signal

    if first_run:
        log('First run')
    else:
        log('Subsequent run')

    sys.exit(app.exec())

class AddPartDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)

        self.setWindowTitle('Add Part')
        layout = QVBoxLayout()

        self.name_line_edit = QLineEdit()
        layout.addWidget(QLabel('Name:'))
        layout.addWidget(self.name_line_edit)

        self.part_number_line_edit = QLineEdit()
        layout.addWidget(QLabel('Part Number:'))
        layout.addWidget(self.part_number_line_edit)

        self.description_line_edit = QLineEdit()
        layout.addWidget(QLabel('Description:'))
        layout.addWidget(self.description_line_edit)

        self.weight_line_edit = QLineEdit()
        layout.addWidget(QLabel('Weight:'))
        layout.addWidget(self.weight_line_edit)

        self.width_line_edit = QLineEdit()
        layout.addWidget(QLabel('Width:'))
        layout.addWidget(self.width_line_edit)

        self.length_line_edit = QLineEdit()
        layout.addWidget(QLabel('Length:'))
        layout.addWidget(self.length_line_edit)

        self.unit_of_measurement_combo = QComboBox()
        self.unit_of_measurement_combo.addItems(['Units', 'Inches', 'Pounds'])
        layout.addWidget(QLabel('Unit of Measurement:'))
        layout.addWidget(self.unit_of_measurement_combo)

        self.price_input = QDoubleSpinBox()
        self.price_input.setPrefix("$")
        self.price_input.setRange(0.0, 999999.99)
        self.price_input.setDecimals(2)
        layout.addWidget(QLabel('Price:'))
        layout.addWidget(self.price_input)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.verify_and_accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        default_processes_section = self.create_default_processes_section()
        layout.addLayout(default_processes_section)

        self.setLayout(layout)

    def verify_and_accept(self):
        unit_of_measurement = self.unit_of_measurement_combo.currentText()

        if not self.name_line_edit.text():
            QMessageBox.warning(self, 'Error', 'Please enter a name.')
            return

        if not self.part_number_line_edit.text():
            QMessageBox.warning(self, 'Error', 'Please enter a part number.')
            return

        if not self.price_input.value():
            QMessageBox.warning(self, 'Error', 'Please enter a price.')
            return

        if unit_of_measurement == 'Inches' and not self.length_line_edit.text():
            QMessageBox.warning(self, 'Error', 'Please enter a length.')
            return

        if unit_of_measurement == 'Pounds':
            if not self.weight_line_edit.text():
                QMessageBox.warning(self, 'Error', 'Please enter a weight.')
                return

            if not self.width_line_edit.text():
                QMessageBox.warning(self, 'Error', 'Please enter a width.')
                return

            if not self.length_line_edit.text():
                QMessageBox.warning(self, 'Error', 'Please enter a length.')
                return

        self.accepted_data = {
            'name': self.name_line_edit.text(),
            'part_number': self.part_number_line_edit.text(),
            'description': self.description_line_edit.text(),
            'weight': self.weight_line_edit.text(),
            'width': self.width_line_edit.text(),
            'length': self.length_line_edit.text(),
            'unit_of_measurement': unit_of_measurement,
            'price': self.price_input.value()
        }

        self.accept()
        self.close()


    def get_data(self):
        return {
            'name': self.name_line_edit.text(),
            'part_number': self.part_number_line_edit.text(),
            'description': self.description_line_edit.text(),
            'weight': self.weight_line_edit.text(),
            'width': self.width_line_edit.text(),
            'length': self.length_line_edit.text(),
            'unit_of_measurement': self.unit_of_measurement_combo.currentText(),
            'price': self.price_input.value()
        }

    def create_default_processes_section(self):
        self.default_processes_label = QLabel("Default Processes:")
        self.default_processes_list = QListWidget()
        self.add_process_button = QPushButton("Add Process")
        self.add_process_button.clicked.connect(self.add_process_to_default_processes)

        layout = QVBoxLayout()
        layout.addWidget(self.default_processes_label)
        layout.addWidget(self.default_processes_list)
        layout.addWidget(self.add_process_button)

        return layout

    def get_available_processes(self):
        # Replace this with the actual code to get the list of available processes from your data source
        available_processes = ["Process 1", "Process 2", "Process 3"]
        return available_processes

    def add_process_to_default_processes(self):
        # Get the list of available processes
        available_processes = self.get_available_processes()

        # Create a QInputDialog with the available processes
        process_name, ok = QInputDialog.getItem(self, "Add Process", "Select a process:", available_processes, 0, False)

        # If the user clicked "OK", add the selected process to the default_processes_list
        if ok:
            process_item = QListWidgetItem(process_name)
            self.default_processes_list.addItem(process_item)

class AddProcessDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Add Process")

        layout = QVBoxLayout()

        # Name field
        self.name_label = QLabel("Name:")
        self.name_edit = QLineEdit()
        layout.addWidget(self.name_label)
        layout.addWidget(self.name_edit)

        # Price field
        self.price_label = QLabel("Price:")
        self.price_edit = QDoubleSpinBox()
        self.price_edit.setPrefix('$')
        self.price_edit.setDecimals(2)
        self.price_edit.setMinimum(0)
        self.price_edit.setMaximum(9999999.99)
        layout.addWidget(self.price_label)
        layout.addWidget(self.price_edit)

        # Unit of Measurement field
        self.unit_of_measurement_label = QLabel("Unit of Measurement:")
        self.unit_of_measurement_combo = QComboBox()
        self.unit_of_measurement_combo.addItems(["inches", "minutes"])
        layout.addWidget(self.unit_of_measurement_label)
        layout.addWidget(self.unit_of_measurement_combo)

        # Notes field
        self.notes_label = QLabel("Notes:")
        self.notes_edit = QLineEdit()
        layout.addWidget(self.notes_label)
        layout.addWidget(self.notes_edit)

        # Buttons
        button_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)

        default_parts_section = self.create_default_parts_section()
        layout.addLayout(default_parts_section)

        self.setLayout(layout)

    def get_data(self):
        name = self.name_edit.text()
        price = self.price_edit.text()
        unit_of_measurement = self.unit_of_measurement_combo.currentText()
        notes = self.notes_edit.text()

        return name, price, unit_of_measurement, notes

    def verify_and_accept(self):
        if not self.name_edit.text().strip():
            QMessageBox.warning(self, 'Error', 'Please enter a name.')
            return

        if not self.price_edit.text().strip():
            QMessageBox.warning(self, 'Error', 'Please enter a price.')
            return

        price = float(self.price_edit.text().strip())
        self.accepted_data = (
            self.name_edit.text().strip(),
            price,
            self.unit_of_measurement_combo.currentText(),
            self.notes_edit.text().strip()
        )
        self.accept()

    def create_default_parts_section(self):
        self.default_parts_label = QLabel("Default Parts:")
        self.default_parts_list = QListWidget()
        self.add_part_button = QPushButton("Add Part")
        self.add_part_button.clicked.connect(self.add_part_to_default_parts)

        layout = QVBoxLayout()
        layout.addWidget(self.default_parts_label)
        layout.addWidget(self.default_parts_list)
        layout.addWidget(self.add_part_button)

        return layout

    def add_part_to_default_parts(self):
        parts_combobox.addItems(parts)

class CustomTableWidget(QTableWidget):
    def __init__(self, *args, **kwargs):
        super(CustomTableWidget, self).__init__(*args, **kwargs)
        self.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.itemDoubleClicked.connect(self.handle_double_click)
        self.customContextMenuRequested.connect(self.show_context_menu)
        self.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)  # Add this line

    def handle_double_click(self, item):
        index = self.indexFromItem(item)
        self.view_entry(index)

    def show_context_menu(self, position):
        context_menu = QMenu(self)
        edit_action = QAction('Edit', self)
        edit_action.triggered.connect(self.edit_item)
        delete_action = QAction('Delete', self)
        delete_action.triggered.connect(self.delete_item)
        view_action = QAction('View', self)
        view_action.triggered.connect(self.view_current_item)
        lock_action = QAction('Lock', self)
        lock_action.triggered.connect(self.lock_item)

        context_menu.addAction(edit_action)
        context_menu.addAction(delete_action)
        context_menu.addAction(view_action)
        context_menu.addAction(lock_action)

        selected_row = self.currentRow()
        if selected_row != -1 and self.item(selected_row, 0):
            if self.objectName() == "quotes_table":
                duplicate_action = QAction('Duplicate', self)
                duplicate_action.triggered.connect(self.duplicate_item)
                context_menu.addAction(duplicate_action)

            context_menu.exec(self.viewport().mapToGlobal(position))

    def edit_entry(self):
        index = self.currentIndex()
        if not index.isValid():
            return

        entry_data = self.get_entry_data(index)
        table_name = self.objectName()

        if table_name == "parts_table":
            fields = [
                ('name', 'Name'),
                ('part_number', 'Part #'),
                ('description', 'Description'),
                ('unit_of_measurement', 'Unit of Measurement'),
                ('weight', 'Weight'),
                ('width', 'Width'),
                ('length', 'Length'),
                ('price', 'Price'),
                ('process', 'Process')
            ]
            units = ["Units", "Inches", "Pounds"]
        elif table_name == "customers_table":
            fields = [
                ('alias', 'Alias'),
                ('name', 'Name'),
                ('description', 'Description'),
                ('notes', 'Notes'),
                ('address_1', 'Address 1'),
                ('address_2', 'Address 2'),
                ('city', 'City'),
                ('state', 'State'),
                ('zip_code', 'Zip Code'),
                ('country', 'Country')
            ]
            units = None
        elif table_name == "quotes_table":
            fields = [
                ('quote_name', 'Quote Name'),
                ('customer', 'Customer')
            ]
            units = None
        elif table_name == "processes_table":
            fields = [
                ('process_name', 'Process Name'),
                ('price', 'Price'),
                ('unit_of_measurement', 'Unit of Measurement'),
                ('notes', 'Notes')
            ]
            units = ["Inches", "Minutes"]
        else:
            raise ValueError(f"Unknown table name: {table_name}")

        # Get the list of part names from the parent
        parts = self.parent().get_parts_list()

        edit_dialog = EditEntryDialog(entry_data, fields, units, parts, self)
        result = edit_dialog.exec()

        if result == QDialog.DialogCode.Accepted:

            # Update the table with the modified data
            for i, (field, _) in enumerate(fields):
                if field == "unit_of_measurement":
                    new_value = edit_dialog.form_widgets[field].currentText()
                elif field == "price":
                    new_value = edit_dialog.form_widgets[field].value()
                else:
                    new_value = edit_dialog.form_widgets[field].text()

                item = QTableWidgetItem(str(new_value))
                self.setItem(index.row(), i, item)

                # Get the entry_id from the first column (assuming it's the ID column)
                entry_id = self.item(index.row(), 0).text()

                # Update the database
                self.update_database(table_name, entry_id, field, new_value)

    def delete_item(self):
        pass

    def view_entry(self, index):
        entry_data = self.get_entry_data(index)
        table_name = self.objectName()

        if table_name == "parts_table":
            fields = [
                ('name', 'Name', None),
                ('part_number', 'Part #', None),
                ('description', 'Description', None),
                ('unit_of_measurement', 'Unit of Measurement', None),
                ('weight', 'Weight', None),
                ('width', 'Width', None),
                ('length', 'Length', None),
                ('price', 'Price', lambda x: f"${x:.2f}")  # Add a lambda function to format the pric
                ]
        elif table_name == "customers_table":
            fields = [
                ('alias', 'Alias'),
                ('name', 'Name'),
                ('description', 'Description'),
                ('notes', 'Notes'),
                ('address_1', 'Address 1'),
                ('address_2', 'Address 2'),
                ('city', 'City'),
                ('state', 'State'),
                ('zip_code', 'Zip Code'),
                ('country', 'Country')
            ]
        elif table_name == "quotes_table":
            fields = [
                ('quote_name', 'Quote Name'),
                ('customer', 'Customer')
            ]
        elif table_name == "processes_table":
            fields = [
                ('process_name', 'Process Name', None),
                ('price', 'Price', lambda x: f"${x:.2f}"),  # Add a lambda function to format the price
                ('unit_of_measurement', 'Unit of Measurement', None),
                ('notes', 'Notes', None)
            ]
        else:
            raise ValueError(f"Unknown table name: {table_name}")

        view_entry_dialog = ViewEntryDialog(entry_data, fields, self, table_name)  # Pass table_name here
        view_entry_dialog.exec()

    def get_entry_data(self, index):
        row = index.row()
        entry_data = {}
    
        if self.objectName() == "parts_table":
            entry_data['name'] = self.item(row, 0).text()
            entry_data['part_number'] = self.item(row, 1).text()
            entry_data['description'] = self.item(row, 2).text()
            entry_data['unit_of_measurement'] = self.item(row, 3).text()
            entry_data['weight'] = self.item(row, 4).text()
            entry_data['width'] = self.item(row, 5).text()
            entry_data['length'] = self.item(row, 6).text()
            price_text = self.item(row, 9).text().strip("$")
            entry_data['price'] = float(price_text) if price_text else 0.0
        elif self.objectName() == "customers_table":
            entry_data['alias'] = self.item(row, 0).text()
            entry_data['name'] = self.item(row, 1).text()
            entry_data['description'] = self.item(row, 2).text()
            entry_data['notes'] = self.item(row, 3).text()
            entry_data['address_1'] = self.item(row, 4).text()
            entry_data['address_2'] = self.item(row, 5).text()
            entry_data['city'] = self.item(row, 6).text()
            entry_data['state'] = self.item(row, 7).text()
            entry_data['zip_code'] = self.item(row, 8).text()
            entry_data['country'] = self.item(row, 9).text()
        elif self.objectName() == "quotes_table":
            entry_data['quote_name'] = self.item(row, 0).text()
            entry_data['customer'] = self.item(row, 1).text()
        elif self.objectName() == "processes_table":
            entry_data['process_name'] = self.item(row, 0).text() if self.item(row, 0) else ''
            price_text = self.item(row, 1).text().strip("$") if self.item(row, 1) else ''
            try:
                entry_data['price'] = float(price_text) if price_text else 0.0
            except ValueError:
                entry_data['price'] = 0.0  # Set the price to 0.0 if it cannot be converted to float
            entry_data['unit_of_measurement'] = self.item(row, 2).text() if self.item(row, 2) else ''
            entry_data['notes'] = self.item(row, 3).text() if self.item(row, 3) else ''
            entry_data['process'] = self.item(row, 4).text() if self.item(row, 4) else ''

        return entry_data

    def get_parts_list(self):
        parts = []
        for row in range(self.rowCount()):
            parts.append(self.item(row, 0).text())
        return parts

    def lock_item(self):
        pass

    def duplicate_item(self):
        pass

    def view_current_item(self):
        index = self.currentIndex()
        self.view_entry(index)

class ViewEntryDialog(QDialog):
    def __init__(self, entry_data, fields, parent=None, table_name=None):  # Add table_name here
        super().__init__(parent)

        self.table_name = table_name  # Set the table_name attribute

        self.setWindowTitle('View Entry')
        layout = QVBoxLayout()

        self.fields = fields  # Initialize the fields attribute

        grid_layout = QGridLayout()

        # Display entry fields using QLabel widgets
        row = 0
        for field_data in fields:
            field, display_name, *format_func = field_data
            if field == "default_parts" or field == "process":  # Skip the "default_parts" and "process" fields
                continue
            key_label = QLabel(display_name)
            value = format_func[0](entry_data[field]) if format_func and format_func[0] else entry_data[field]
            value_label = QLabel(str(value))
            grid_layout.addWidget(key_label, row, 0)
            grid_layout.addWidget(value_label, row, 1)
            row += 1

        layout.addLayout(grid_layout)

        # Add the parts section
        default_parts = entry_data.get("default_parts", [])  # Get the default_parts, or assign an empty list if it doesn't exist
        parts_section = self.create_parts_section(default_parts)
        layout.addLayout(parts_section)

        # Add the "Edit" button
        edit_button = QPushButton("Edit")
        edit_button.clicked.connect(self.edit_entry)
        layout.addWidget(edit_button, alignment=Qt.AlignmentFlag.AlignRight)

        # Add the "Close" button
        close_button = QPushButton("Close")
        close_button.clicked.connect(self.close)
        layout.addWidget(close_button, alignment=Qt.AlignmentFlag.AlignRight)

        self.entry_data = entry_data
        self.setLayout(layout)

    def edit_entry(self):
        if self.table_name == "parts_table":
            units = ["Units", "Inches", "Pounds"]
        elif self.table_name == "processes_table":
            units = ["Inches", "Minutes"]
        else:
            units = None
        edit_dialog = EditEntryDialog(self.entry_data, self.fields, units, self.parent())
        result = edit_dialog.exec()

        if result == QDialog.DialogCode.Accepted:
            # Update the table with the modified data
            index = self.parent().currentIndex()
            for i, (field, _, _) in enumerate(self.fields):
                if field == "unit_of_measurement":
                    new_value = edit_dialog.form_widgets[field].currentText()
                else:
                    new_value = edit_dialog.form_widgets[field].text()
                item = QTableWidgetItem(new_value)
                self.parent().setItem(index.row(), i, item)

            # Close the view dialog
            self.accept()

    def create_parts_section(self, default_parts):
        parts_label = QLabel("Default Parts:")
        parts_list = QListWidget()

        # Fill the parts_list with default_parts
        for part in default_parts:
            parts_list.addItem(part)

        layout = QVBoxLayout()
        layout.addWidget(parts_label)
        layout.addWidget(parts_list)

        return layout

class EditEntryDialog(QDialog):
    def __init__(self, entry_data, fields, units, parts, parent=None):
        super().__init__(parent)
        self.parts = parts

        self.setWindowTitle('Edit Entry')
        layout = QVBoxLayout()

        form_layout = QFormLayout()
        self.form_widgets = {}

        for field_data in fields:
            field, label, *format_func = field_data
            if field == "unit_of_measurement":
                widget = self.create_unit_of_measurement_combobox(units)
                widget.setCurrentText(entry_data.get(field, ""))
            elif field == "price":
                widget = QDoubleSpinBox()
                widget.setRange(0, 1000000)
                widget.setPrefix("$")
                widget.setDecimals(2)
                widget.setValue(float(entry_data.get(field, 0)))
            else:
                widget = QLineEdit(str(entry_data.get(field, "")))

            self.form_widgets[field] = widget
            form_layout.addRow(QLabel(label), widget)

        layout.addLayout(form_layout)
        layout.addLayout(self.create_default_parts_section())

        button_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel, self)
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)

        self.setLayout(layout)

    def create_unit_of_measurement_combobox(self, units):
        unit_of_measurement_combobox = QComboBox()

        # Populate the combo box with the units
        for unit in units:
            unit_of_measurement_combobox.addItem(unit)

        return unit_of_measurement_combobox

    def create_default_parts_section(self):
        self.default_parts_label = QLabel("Default Parts:")
        self.default_parts_list = QListWidget()
        self.add_part_button = QPushButton("Add Part")
        self.add_part_button.clicked.connect(self.add_part_to_default_parts)

        layout = QVBoxLayout()
        layout.addWidget(self.default_parts_label)
        layout.addWidget(self.default_parts_list)
        layout.addWidget(self.add_part_button)

        # Define parts_combobox as an instance variable
        self.parts_combobox = QComboBox()
        self.parts_combobox.addItems(self.parts)
        layout.addWidget(self.parts_combobox)

        return layout

    def add_part_to_default_parts(self):
        # Add code to open a part selection dialog and add the selected part to self.default_parts_list
        parts_selection_dialog = QDialog(self)
        parts_selection_dialog.setWindowTitle("Select Part")
        layout = QVBoxLayout()

        # Use self.parts_combobox instead of parts_combobox
        layout.addWidget(self.parts_combobox)

        button_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel, self)
        button_box.accepted.connect(parts_selection_dialog.accept)
        button_box.rejected.connect(parts_selection_dialog.reject)
        layout.addWidget(button_box)

        parts_selection_dialog.setLayout(layout)

        result = parts_selection_dialog.exec()
        if result == QDialog.DialogCode.Accepted:

            selected_part = self.parts_combobox.currentText()
            self.default_parts_list.addItem(selected_part)

def update_database_entry(self, row, column, new_value):
    log(f'Updating database entry for row {row}, column {column} with new value: {new_value}')

if __name__ == '__main__':
    setup_logging()
    initialize_database()  # Call the initialize_database function before running the app
    main()
