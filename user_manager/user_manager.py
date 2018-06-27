import datetime
import functools
import re

import jwt
from flask import Flask, request, send_from_directory, redirect
from flask_mail import Mail, Message
from flask_restful import Resource, Api, abort
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

import config

app = Flask(__name__, static_folder='static/ui/build')
app.config['SQLALCHEMY_DATABASE_URI'] = config.connection_string
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config.from_object('config')
db = SQLAlchemy(app)
api = Api(app)
mail = Mail(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), nullable=False, unique=True)
    password = db.Column(db.String(128), nullable=False)
    confirmed_at = db.Column(db.DateTime())
    is_enabled = db.Column(db.Boolean(), nullable=False, default=False)

    def __init__(self, email, password, ):
        self.email = email
        self.password = password

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
            abort(400, message='Please enter a valid email')
        if len(password) < 6:
            abort(400, message='password is too short.')

        existing_user = User.query.filter_by(email=email).first()
        if existing_user and existing_user.active:
            abort(400, message='email is alread used.')
        else:
            user = User(email=email,
                        password=generate_password_hash(password),
                        )
            db.session.add(user)
            db.session.commit()

        exp = datetime.datetime.utcnow() + datetime.timedelta(days=app.config['ACTIVATION_EXPIRE_DAYS'])
        encoded = jwt.encode({'email': email, 'exp': exp},
                             app.config['KEY'], algorithm='HS256')

        message = 'Please follow this link to activate your account: http://127.0.0.1:5000/api/users/activate?token={}'.format(
            encoded.decode('utf-8'))
        msg = Message(recipients=[email],
                      body=message,
                      subject='Activation Code')
        mail.send(msg)
        return {'email': email}


class Login(Resource):
    def post(self):
        data = request.json
        email = data['email']
        if not re.match(r'^[A-Za-z0-9.+_-]+@[A-Za-z0-9._-]+\.[a-zA-Z]*$', email):
            abort(400, message='Please enter a valid email')
        password = data['password']
        user = User.query.filter_by(email=email).first()
        if not user:
            abort(400, message='Invalid Username/Password')

        if not check_password_hash(user.password, password):
            abort(400, message='Password is incorrect.')
        exp = datetime.datetime.utcnow() + datetime.timedelta(hours=app.config['TOKEN_EXPIRE_HOURS'])
        encoded = jwt.encode({'email': email, 'exp': exp},
                             app.config['KEY'], algorithm='HS256')
        return {'email': email, 'token': encoded.decode('utf-8'), 'is_activated': user.is_enabled}


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
        user.confirmed_at = datetime.datetime.now()
        db.session.commit()
        return redirect("/login", code=302)


class StaticEnd(Resource):
    def get(self, path):
        return send_from_directory('static/ui/build/static/js/', path)


api.add_resource(Register, '/api/users/register')
api.add_resource(Login, '/api/users/login')
api.add_resource(Activate, '/api/users/activate')
api.add_resource(StaticEnd, '/static/js/<path>')


@app.route('/register')
@app.route('/login')
@app.route('/')
def handle_react():
    return send_from_directory('static/ui/build/', 'index.html')


if __name__ == '__main__':
    app.run(debug=True)
