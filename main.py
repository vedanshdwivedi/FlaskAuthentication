from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid
import jwt
from datetime import datetime, timedelta
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'superSecretKey'
app.config['AUTH_ALGORITHM'] = 'HS256'
app.config["SQLALCHEMY_DATABASE_URI"] = 'sqlite:///todo.db'

db = SQLAlchemy(app)


def token_required(f):

    @wraps(f)
    def decorator(*args, **kwargs):
        token = request.headers.get('x-access-token', None)
        if token is None:
            return make_response(
                jsonify({"message": "Auth Token is Required"}), 403,
                {'WWW-Authenticate': 'Basic realm="Login Required"'})
        try:
            data = jwt.decode(token, app.config["SECRET_KEY"],
                              app.config["AUTH_ALGORITHM"])
            current_user = User.query.filter_by(
                public_id=data['public_id']).first()
        except:
            return make_response(
                jsonify({"message": "Invalid Token Passed"}), 403,
                {'WWW-Authenticate': 'Basic realm="Login Required"'})
        return f(current_user, *args, **kwargs)

    return decorator


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
@token_required
def get_all_users(current_user):
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
@token_required
def get_user_by_id(current_user, public_id):
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
@token_required
def promote_user(current_user, public_id):
    if not current_user.admin:
        return make_response(
            jsonify({"message": "Access Denied to perform this operation"}),
            403)
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return make_response('No User Found', 403)
    user.admin = True
    db.session.commit()

    return make_response(jsonify({'message': 'User Promoted to Admin'}), 200)


@app.route("/user/<public_id>", methods=["DELETE"])
@token_required
def delete_user(current_user, public_id):
    if not current_user.admin:
        return make_response(
            jsonify({"message": "Access Denied to perform this operation"}),
            403)
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return make_response('No User Found', 403)
    db.session.delete(user)
    db.session.commit()

    return make_response(jsonify({'message': 'User Deleted'}), 200)


@app.route("/login", methods=["POST"])
def login():
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return make_response(
            jsonify({"message": "Username and Password Required"}), 401,
            {'WWW-Authenticate': 'Basic realm="Login Required"'})
    user = User.query.filter_by(name=auth.username).first()
    if not user:
        return make_response(
            jsonify({"message": "User Not Found"}), 403,
            {'WWW-Authenticate': 'Basic realm="Login Required"'})
    if check_password_hash(user.password, auth.password):
        # generate token
        token = jwt.encode(
            {
                "public_id": user.public_id,
                "exp": datetime.utcnow() + timedelta(minutes=30)
            }, app.config["SECRET_KEY"], app.config['AUTH_ALGORITHM'])
        return make_response(
            jsonify({
                "message": "Successfully Logged In",
                "token": token
            }), 200)
    else:
        return make_response(jsonify({"message": "Invalid Username/Password"}),
                             403)


@app.route("/")
def index():
    return "You are on index page"

@app.route('/todo', methods=["GET"])
@token_required
def get_all_todo(current_user):
    todos = Todo.query.filter_by(user_id=current_user.id)
    output = []
    for todo in todos:
        todo_data = {}
        todo_data["id"] = todo.id
        todo_data["text"] = todo.text
        todo_data["complete"] = todo.complete
        output.append(todo_data)
    return make_response(jsonify({"todos": output}), 200)

@app.route('/todo/<todo_id>', methods=['GET'])
@token_required
def get_todo_by_id(current_user, todo_id):
    todo = Todo.query.filter_by(id=todo_id).first()
    if not todo:
        return make_response(jsonify({"message": "No Todo Found"}), 403)
    if current_user.id != todo.user_id:
        return make_response(jsonify({
            "message": "This ID does not belong to this user"
        }), 401)
    return make_response(jsonify({"text": todo.text, "complete": todo.complete, "id": todo.user_id}), 200)

@app.route('/todo', methods=["POST"])
@token_required
def create_todo(current_user):
    data = request.get_json()
    new_todo = Todo(text=data['text'],
                    complete=False,
                    user_id=current_user.id)
    db.session.add(new_todo)
    db.session.commit()
    return make_response(
        jsonify({"message": "Todo Created"}),
        200,
    )

@app.route('/toggle_todo/<todo_id>', methods=["GET"])
@token_required
def toggle_todo_completion(current_user, todo_id):
    todo = Todo.query.filter_by(id=todo_id).first()
    if not todo:
        return make_response(jsonify({"message": "No Todo Found"}), 403)
    if current_user.id != todo.user_id:
        return make_response(jsonify({
            "message": "This ID does not belong to this user"
        }), 401)
    todo.complete = not todo.complete
    db.session.commit()
    return make_response(jsonify({"message": "Todo Toggled"}), 200)

@app.route('/todo/<todo_id>', methods=["DELETE"])
@token_required
def delete_todo(current_user, todo_id):
    todo = Todo.query.filter_by(id=todo_id).first()
    if not todo:
        return make_response(jsonify({"message": "No Todo Found"}), 403)
    if current_user.id != todo.user_id:
        return make_response(jsonify({
            "message": "This ID does not belong to this user"
        }), 401)
    db.session.delete(todo)
    db.session.commit()
    return make_response(jsonify({"message": "Todo Deleted"}), 200)

@app.route('/todo/<todo_id>', methods=["PUT"])
@token_required
def update_todo(current_user, todo_id):
    data = request.get_json()
    todo = Todo.query.filter_by(id=todo_id).first()
    if not todo:
        return make_response(jsonify({"message": "No Todo Found"}), 403)
    if current_user.id != todo.user_id:
        return make_response(jsonify({
            "message": "This ID does not belong to this user"
        }), 401)
    flag = False
    if data.get("text") is not None:
        todo.text = data["text"]
        flag = True
    if data.get("complete") is not None:
        todo.complete = data["complete"]
        flag = True
    if flag:
        db.session.commit()
    return make_response(jsonify({"message": "Todo Updated"}), 200)


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True, port=81)
