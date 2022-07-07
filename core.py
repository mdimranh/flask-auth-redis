from functools import wraps
import json
from flask import Flask, jsonify, make_response, request
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
import os
import jwt
import redis

from datetime import datetime, timedelta

from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or '2Q5cGzgCf4bybZ4AGvIR5LZkgNBrgDw0onqXzqKY'

# database name
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL') or \
    'sqlite:///' + os.path.join(basedir, 'database.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True

# creates SQLALCHEMY object
db = SQLAlchemy(app)
migrate = Migrate(app, db)

r = redis.Redis(host='localhost', port=6379, db=0)


class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(300), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(25))

    def __repr__(self):
        return '<User %r>' % self.name

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        if not token:
            return jsonify({'message': 'Token is missing !!'}), 401
        
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.filter_by(id = data['id']).first()

        except:
            return jsonify({'message': 'Token is invalid !!'}), 401

        return f(current_user, *args, **kwargs)
    
    return decorated


@app.route('/api/user', methods =['GET'])
@token_required
def get_all_users(current_user):
    users = User.query.all()
    output = []
    for user in users:
        output.append({
            'id': user.id,
            'name' : user.name,
            'email' : user.email
        })
  
    return jsonify({'users': output})

@app.route('/api/user/profile', methods = ['GET'])
@token_required
def Profile(current_user):
    output = []
    output.append({
        'id': current_user.id,
        'name' : current_user.name,
        'email' : current_user.email
    })
    return jsonify({'users': output})


@app.route('/api/user/<int:id>', methods = ['GET'])
def get_user(id):
    if r.get(f"user_{id}"):
        print("----- > From redis")
        output = r.get(f"user_{id}")
        return jsonify({'user': json.loads(output)})
    else:
        print("----- > From db")
        output = User.query.get(id)
        data = []
        data.append({
                'id': output.id,
                'name': output.name,
                'email': output.email
            })
        r.set(f"user_{id}", json.dumps(data))
        return jsonify({'user': data})


@app.route('/api/login', methods =['POST'])
def login():
    auth = request.form
    if not auth or not auth.get('email') or not auth.get('password'):
        return make_response(
            'Could not verify',
            401,
            {'WWW-Authenticate': 'Basic realm = "Login required !!"'}
        )

    user = User.query.filter_by(email = auth.get('email')).first()

    if not user:
        return make_response(
            'Could not verify',
            401,
            {'WWW-Authenticate' : 'Basic realm ="User does not exist !!"'}
        )

    if user.check_password(auth.get('password')):
        token = jwt.encode({
            'id': user.id,
            'exp' : datetime.utcnow() + timedelta(minutes = 30)
        }, app.config['SECRET_KEY'])
  
        return make_response(jsonify({'token' : token}), 201)

    return make_response(
        'Could not verify',
        403,
        {'WWW-Authenticate' : 'Basic realm ="Wrong Password !!"'}
    )

@app.route('/api/signup', methods=['POST'])
def ApiSignup():
    data = request.form
    print(data)
    if not data or not data.get('email') or not data.get('password'):
        return jsonify({'Error': 'You have not send all required data.'})

    user = User.query.filter_by(email = data.get('email')).first()
    
    if not user:
        user = User(name=data.get('name'), email = data.get('email'))
        user.set_password(data.get('password'))
        db.session.add(user)
        db.session.commit()
        return jsonify({'Success': 'Account create successfully.'})

    else:
        return jsonify({'Error': 'Account already exists !!'})


@app.route('/api/user/delete/<int:id>', methods = ['GET'])
def user_delete(id):
    if r.get(f"user_{id}"):
        print("----- > Delete from redis")
        r.delete(f"user_{id}")
        user = User.query.get(id)
        if user:
            print("----- > Delete from db")
            db.session.delete(user)
            db.session.commit()
            return jsonify({'message': 'User deleted successfully'})
        else:
            return jsonify({'message': 'User is not exists.'})

    else:
        user = User.query.get(id)
        if user:
            print("----- > delete from db")
            db.session.delete(user)
            db.session.commit()
            return jsonify({'message': 'User deleted successfully'})
        else:
            return jsonify({'message': 'User is not exists.'})

@app.route('/api/user/update', methods = ['POST'])
@token_required
def user_update(current_user):
    new_data = request.form
    if new_data:
        user = User.query.filter_by(id = current_user.id).first()
        if new_data['name']:
            user.name = new_data['name']
        if new_data['email']:
            user.email = new_data['email']
        db.session.commit()
    user = User.query.filter_by(id = current_user.id).first()
    data = []
    data.append(
        {
            'id': user.id,
            'name': user.name,
            'email': user.email
        }
    )
    if r.get(f'user_{user.id}'):
        print("get into redis")
        r.delete(f'user_{user.id}')
        r.add(f'user_{user.id}', json.dumps(data))
    return jsonify({'datas': data})
    


if __name__ == '__main__':
    app.run(debug=True)