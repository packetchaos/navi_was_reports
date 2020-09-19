import sqlite3
from sqlite3 import Error


def new_db_connection(db_file):
    # create a connection to our database
    conn = None
    try:
        # A database file will be created if one doesn't exist
        conn = sqlite3.connect(db_file, timeout=5.0)
    except Error as E:
        print(E)
    return conn


def drop_tables(conn, table):
    try:
        drop_table = '''DROP TABLE {}'''.format(table)
        cur = conn.cursor()
        cur.execute('pragma journal_mode=wal;')
        cur.execute(drop_table)
    except Error:
        pass


def create_table(conn, table_information):
    try:
        c = conn.cursor()
        c.execute('pragma journal_mode=wal;')
        c.execute(table_information)
    except Error as e:
        print(e)


def create_apps_table():
    database = r"was.db"
    app_conn = new_db_connection(database)
    create_apps = """CREATE TABLE IF NOT EXISTS apps (
                            name text,
                            uuid text PRIMARY KEY, 
                            target text, 
                            scan_completed_time text,
                            pages_audited text,
                            pages_crawled text,
                            requests_made text, 
                            critical_count text,
                            high_count text,
                            medium_count text,
                            low_count text, 
                            info_count text,
                            owasp text,
                            tech_list text,
                            config_id text
                            );"""
    app_conn.execute('pragma journal_mode=wal;')

    create_table(app_conn, create_apps)


def insert_apps(conn, apps):
    sql = '''INSERT or IGNORE into apps(
             name,
             uuid, 
             target, 
             scan_completed_time,
             pages_audited,
             pages_crawled,
             requests_made, 
             critical_count,
             high_count,
             medium_count,
             low_count, 
             info_count,
             owasp,
             tech_list,
             config_id)
     VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)'''
    cur = conn.cursor()
    cur.execute('pragma journal_mode=wal;')
    cur.execute(sql, apps)
