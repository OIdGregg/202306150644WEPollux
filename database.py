import mysql.connector
from mysql.connector import Error

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
