import mysql.connector
from mysql.connector import Error

def initialize_database():
    connection = create_database_connection()
    cursor = connection.cursor()
    
    # Removed the settings table creation, as the admin setup has been removed
    # Added IF NOT EXISTS to all table creation statements

    cursor.execute('''CREATE TABLE IF NOT EXISTS user_groups (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(255) NOT NULL
        );''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS permissions (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(255) NOT NULL
        );''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(255) NOT NULL,
            password_hash CHAR(60) NOT NULL,
            user_group_id INT,
            FOREIGN KEY (user_group_id) REFERENCES user_groups(id)
        );''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS user_group_permissions (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_group_id INT NOT NULL,
            permission_id INT NOT NULL,
            FOREIGN KEY (user_group_id) REFERENCES user_groups(id),
            FOREIGN KEY (permission_id) REFERENCES permissions(id)
        );''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS materials (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            unit ENUM('kg', 'lb') NOT NULL,
            category VARCHAR(255) NOT NULL
        );''')
    connection.commit()
    cursor.close()
    connection.close()

def update_database(self, table_name, entry_id, field, new_value):
    cursor = self.db.cursor()
    update_query = f"UPDATE {table_name} SET {field} = %s WHERE id = %s"
    cursor.execute(update_query, (new_value, entry_id))
    self.db.commit()

def execute_query(connection, query):
    cursor = connection.cursor()
    try:
        cursor.execute(query)
        if query.lower().startswith("select"):
            result = cursor.fetchall()
        else:
            connection.commit()
            result = None
    except mysql.connector.Error as e:
        print(f"The error '{e}' occurred")
        result = None
    finally:
        cursor.close()
    return result


def check_first_run():
    connection = create_database_connection()
    cursor = connection.cursor()
    cursor.execute('SELECT COUNT(*) FROM settings')
    row_count = cursor.fetchone()[0]
    cursor.close()
    connection.close()
    print('Row count:', row_count)
    return (row_count == 0)


def admin_role_exists(connection):
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM user_roles WHERE role_name = 'Administrators'")
    result = cursor.fetchone()
    exists = result is not None
    print("Admin role exists: %s", exists)
    return exists


def admin_user_exists(connection):
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM users WHERE username = 'Administrator'")
    result = cursor.fetchone()
    exists = result is not None
    print("Admin user exists: %s", exists)
    return exists


def create_database_connection():
    connection = mysql.connector.connect(host='localhost', user='estimator', password='P0llux2023!')
    return connection
