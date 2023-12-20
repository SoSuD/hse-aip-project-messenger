import pymysql
import pymysql.cursors
import pymysql_pool


def create_connection():
    return pymysql.connect(host='89.163.138.69',
                           user='messenger_project',
                           password='2sU6c3ubifA0',
                           db='dinar_messenger',
                           autocommit=True,
                           connect_timeout=5)


def create_pool():
    return pymysql_pool.Pool(host='89.163.138.69',
                             user='messenger_project',
                             password='2sU6c3ubifA0',
                             cursorclass=pymysql.cursors.DictCursor,
                             db='dinar_messenger',
                             autocommit=True)


