from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'superSecretKey'
app.config['AUTH_ALGORITHM'] = 'HS256'
app.config["SQLALCHEMY_DATABASE_URI"] = 'sqlite:///todo.db'

db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50))
    password = db.Column(db.String(50))
    admin = db.Column(db.Boolean)


class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(50))
    complete = db.Column(db.Boolean)
    user_id = db.Column(db.Integer)


@app.route("/users", methods=["GET"])
def get_all_users():
    users = User.query.all()
    output = []
    for user in users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['name'] = user.name
        user_data['password'] = user.password
        user_data['admin'] = user.admin
        output.append(user_data)
    return make_response(jsonify({'users': output}), 200)


@app.route("/user/<public_id>", methods=["GET"])
def get_user_by_id(public_id):
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return make_response('No User Found', 403)
    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['name'] = user.name
    user_data['password'] = user.password
    user_data['admin'] = user.admin
    return make_response(jsonify({'user': user_data}), 200)


@app.route("/user", methods=["POST"])
def create_user():
    data = request.get_json()
    hashed_password = generate_password_hash(data["password"], method='sha256')
    new_user = User(public_id=str(uuid.uuid4()),
                    name=data['name'],
                    password=hashed_password,
                    admin=False)
    db.session.add(new_user)
    db.session.commit()
    return make_response(
        jsonify({"message": "User Created"}),
        200,
    )


@app.route("/user/<public_id>", methods=["PUT"])
def promote_user(public_id):
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return make_response('No User Found', 403)
    user.admin = True
    db.session.commit()

    return make_response(jsonify({'message': 'User Promoted to Admin'}), 200)


@app.route("/user/<public_id>", methods=["DELETE"])
def delete_user(public_id):
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return make_response('No User Found', 403)
    db.session.delete(user)
    db.session.commit()

    return make_response(jsonify({'message': 'User Deleted'}), 200)


@app.route("/")
def index():
    return "You are on index page"


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True, port=81)
