from flask import Flask, request, make_response
from functools import wraps


def auth_required(fun):

    @wraps(fun)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if auth and auth.username == "username1" and auth.password == "password":
            return fun(*args, **kwargs)
        else:
            return make_response(
                "Could not verify", 401,
                {'WWW-Authenticate': 'Basic realm="Login Required"'})

    return decorated


app = Flask(__name__)


@app.route('/')
def index():
    if request.authorization and request.authorization.username == 'username' and request.authorization.password == "password":
        return "You are logged In"
    else:
        return make_response(
            "Could not verify", 401,
            {'WWW-Authenticate': 'Basic realm="Login Required"'})


@app.route('/page')
@auth_required
def page():
    return "You are on Page"


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True, port=81)
