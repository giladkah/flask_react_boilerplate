import datetime
import functools
import re

import jwt
from flask import Flask, request
from flask_cors import CORS
from flask_mail import Mail, Message
from flask_restful import Resource, Api, abort
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

import config

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = config.connection_string
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config.from_object('config')
db = SQLAlchemy(app)
api = Api(app)
mail = Mail(app)
cors = CORS(app, resources={r"/users/*": {"origins": "*"}})


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    # User email information
    email = db.Column(db.String(255), nullable=False, unique=True)
    username = db.Column(db.String(50), nullable=False, unique=True)
    password = db.Column(db.String(128), nullable=False)
    confirmed_at = db.Column(db.DateTime())

    # User information
    is_enabled = db.Column(db.Boolean(), nullable=False, default=False)
    first_name = db.Column(db.String(50), nullable=False, default='')
    last_name = db.Column(db.String(50), nullable=False, default='')

    def __init__(self, email, username, password, first_name, last_name):
        self.email = email
        self.username = username
        self.password = password
        self.first_name = first_name
        self.last_name = last_name

    def is_active(self):
        return self.is_enabled


def login_required(method):
    @functools.wraps(method)
    def wrapper(self):
        header = request.headers.get('Authorization')
        _, token = header.split()
        try:
            decoded = jwt.decode(token, app.config['KEY'], algorithms='HS256')
        except jwt.DecodeError:
            abort(400, message='Token is not valid.')
        except jwt.ExpiredSignatureError:
            abort(400, message='Token is expired.')
        email = decoded['email']
        existing_user = User.query.filter_by(email=email).first()
        if not existing_user:
            abort(400, message='User is not found.')
        return method(self, existing_user)

    return wrapper


class Register(Resource):
    def post(self):
        data = request.json
        email = data['email']
        password = data['password']
        if not re.match(r'^[A-Za-z0-9.+_-]+@[A-Za-z0-9._-]+\.[a-zA-Z]*$', email):
            abort(400, message='email is not valid.')
        if len(password) < 6:
            abort(400, message='password is too short.')

        existing_user = User.query.filter_by(email=email).first()
        if existing_user and existing_user.active:
            abort(400, message='email is alread used.')
        else:
            user = User(email=email,
                        username=data['username'],
                        password=generate_password_hash(password),
                        first_name=data['firstName'],
                        last_name=data['lastName']
                        )
            db.session.add(user)
            db.session.commit()

        exp = datetime.datetime.utcnow() + datetime.timedelta(days=app.config['ACTIVATION_EXPIRE_DAYS'])
        encoded = jwt.encode({'email': email, 'exp': exp},
                             app.config['KEY'], algorithm='HS256')
        #
        # message = 'Please follow this link to activate your account: http://127.0.0.1:5000/users/activate?token={}'.format(
        #     encoded.decode('utf-8'))
        # msg = Message(recipients=[email],
        #               body=message,
        #               subject='Activation Code')
        # mail.send(msg)
        return {'email': email, 'message': 'adasdadssad'}


class Login(Resource):
    def post(self):
        data = request.json
        email = data['email']
        password = data['password']
        user = User.query.filter_by(email=email).first()
        if not user:
            abort(400, message='User is not found.')

        if not check_password_hash(user.password, password):
            abort(400, message='Password is incorrect.')
        exp = datetime.datetime.utcnow() + datetime.timedelta(hours=app.config['TOKEN_EXPIRE_HOURS'])
        encoded = jwt.encode({'email': email, 'exp': exp},
                             app.config['KEY'], algorithm='HS256')
        return {'email': email, 'token': encoded.decode('utf-8')}


class Activate(Resource):
    def get(self):
        activation_code = request.args['token']
        try:
            decoded = jwt.decode(activation_code, app.config['KEY'], algorithms='HS256')
        except jwt.DecodeError:
            abort(400, message='Activation code is not valid.')
        except jwt.ExpiredSignatureError:
            abort(400, message='Activation code is expired.')
        email = decoded['email']
        user = User.query.filter_by(email=email).first()
        user.is_enabled = True
        db.session.commit()
        # TODO: when on same server redirect to login page
        return {'email': email}


api.add_resource(Register, '/users/register')
api.add_resource(Login, '/users/login')
api.add_resource(Activate, '/users/activate')

if __name__ == '__main__':
    app.run()
