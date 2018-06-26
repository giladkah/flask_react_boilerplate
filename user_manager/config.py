import os

db_host = os.environ.get('db_host', 'localhost')
db_port = os.environ.get('port', 5433)
db_user = os.environ.get('db_user', 'postgres')
db_password = os.environ.get('db_password', 'postgres')
db_name = os.environ.get('db_name', 'user-manager')
connection_string = "postgresql://{db_user}:{db_password}@{db_host}:{db_port}/{db_name}".format(**{
    'db_user': db_user,
    'db_host': db_host,
    'db_port': db_port,
    'db_password': db_password,
    'db_name': db_name,
})

DEBUG = True

MAIL_SERVER = 'smtp.gmail.com'
MAIL_PORT = 587
# MAIL_USE_SSL = True



MAIL_USE_TLS = True

MAIL_USERNAME = ''
MAIL_PASSWORD = ''
MAIL_DEFAULT_SENDER = ''

KEY = 'secret'
ACTIVATION_EXPIRE_DAYS = 5
TOKEN_EXPIRE_HOURS = 1
