from flask import Flask, jsonify, request, make_response
import jwt
from datetime import datetime, timedelta
from functools import wraps


app = Flask(__name__)
app.config['SECRET_KEY'] = 'superSecretKey'
app.config['AUTH_ALGORITHM'] = 'HS256'

def check_auth(fun):
  @wraps(fun)
  def decorator(*args, **kwargs):
    token = request.args.get('token')

    if not token:
      return jsonify({'message': 'Token not Present'}), 403
    
    try:
        data = jwt.decode(token, app.config['SECRET_KEY'], app.config['AUTH_ALGORITHM'])
    except Exception as ex:
        return jsonify({'message': 'Token is Invalid'}), 403
    return fun(*args, **kwargs)
    
  return decorator
    

@app.route('/unprotected')
def unprotected():
    return "You are on Unprotected Page"


@app.route('/protected')
@check_auth
def protected():
    return "You are on Protected Page"


@app.route('/login')
def login():
    auth = request.authorization
    if auth and auth.password == "password":
        token = jwt.encode(
            {
                'user': auth.username,
                "exp": datetime.utcnow() + timedelta(seconds=30)
            }, app.config['SECRET_KEY'], app.config['AUTH_ALGORITHM'])
        return jsonify({'token': token})
    return make_response("Could not verify", 401,
                         {'WWW-Authenticate': 'Basic realm="Login Required"'})


@app.route("/")
def index():
    return "You are on index page"


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True, port=81)
