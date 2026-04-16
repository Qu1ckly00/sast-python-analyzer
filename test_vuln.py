import sqlite3

def get_user(username):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Небезпечно! Класична SQL-ін'єкція через f-рядок
    cursor.execute(f"SELECT * FROM users WHERE name = '{username}'")
    
    # Небезпечно! SQL-ін'єкція через конкатенацію
    query = "SELECT * FROM users WHERE name = '" + username + "'"
    cursor.execute(query)

get_user("admin' OR '1'='1")