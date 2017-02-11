import os
import requests
from flask import Flask, render_template, request
from wtforms.fields import StringField, PasswordField
from flask_wtf import FlaskForm
from flask.ext.sqlalchemy import SQLAlchemy
from wtforms.validators import DataRequired

app = Flask(__name__)
# the configs!
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///db.sqlite')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = os.environ.get('SECRET_KEY', 'ayyyyyy')
LOGIN_ID = os.environ.get('LOGIN_ID')
LOGIN_PASSWORD = os.environ.get('LOGIN_PASSWORD')
FINAPP_ID = os.environ.get('FINAPP_ID', "10003600")
REST_URL = os.environ.get('REST_URL', "https://rest.developer.yodlee.com/services/srest/restserver/v1.0/")
NODE_URL = os.environ.get('NODE_URL', "https://node.developer.yodlee.com/authenticate/restserver/")
API_V2_URL = os.environ.get('API_URL', 'https://developer.api.yodlee.com/ysl/restserver/v1')

db = SQLAlchemy(app)


class ApiError(Exception):
    pass


class User(db.Model):
    name = db.Column(db.String(800), primary_key=True)
    user_token = db.Column(db.String(2048))


@app.route('/', methods=('GET', 'POST'))
def index():
    form = LoginForm()
    response = None
    user_token = None
    token = None
    if form.validate_on_submit():
        # todo cache this
        cobSessionToken = get_cobSessionToken()
        # login the user
        user_token = get_userSessionToken(form.username.data, form.password.data, cobSessionToken)
        # save it in db
        u = User.query.filter(User.name == form.username.data).first()
        if u is None:
            u = User(name=form.username.data)
        u.user_token = user_token
        db.session.add(u)
        db.session.commit()
        # accounts = get_accounts(cobSessionToken, user_token)
        # transactions = get_transactions(cobSessionToken, user_token)
        # response = [accounts, transactions]
        token = get_token(cobSessionToken, user_token)
    return render_template(
        'index.html',
        form=form,
        response=response,
        user_token=user_token,
        token=token
    )


@app.route('/ifame_')
def iframe():
    token = request.args['token']
    user_token = request.args['user_token']
    return render_template(
        'iframe.html',
        NODE_URL=NODE_URL,
        FINAPP_ID=FINAPP_ID,
        user_token=user_token,
        token=token
    )


def get_accounts(cobSessionToken, user_token):
    auth = get_header(cobSessionToken, user_token)
    r = requests.get(API_V2_URL + '/accounts', headers={'Authorization': auth})
    if r.status_code != 200:
        raise ApiError(r.json())
    return r.json()


def get_transactions(cobSessionToken, user_token):
    auth = get_header(cobSessionToken, user_token)
    r = requests.get(API_V2_URL + '/transactions', headers={'Authorization': auth})
    if r.status_code != 200:
        raise ApiError(r.json())
    return r.json()


class LoginForm(FlaskForm):
    username = StringField('Username', validators=(DataRequired(),))
    password = PasswordField('Password', validators=(DataRequired(),))


def get_header(cobSession, userSession):
    v = '{cobSession=%s,userSession=%s}' % (cobSession, userSession)
    return v


def get_cobSessionToken():
    # take session-id
    data = {'cobrandPassword': LOGIN_PASSWORD, 'cobrandLogin': LOGIN_ID}
    headers = {'Content-type': 'application/x-www-form-urlencoded', 'charset': 'UTF-8'}
    r0 = requests.post(REST_URL + 'authenticate/coblogin', data=data, headers=headers)
    d0 = r0.json()  # also has other details
    if 'Error' in d0:
        raise ApiError(d0)
    return d0['cobrandConversationCredentials']['sessionToken']


def get_userSessionToken(user_id, user_password, cobSessionToken):
    data = {"login": user_id, "password": user_password, "cobSessionToken": cobSessionToken}
    r1 = requests.post(REST_URL + "authenticate/login", data=data)
    d1 = r1.json()

    return d1["userContext"]["conversationCredentials"]["sessionToken"]


def get_token(cobSessionToken, user_token):
    data = {"cobSessionToken": cobSessionToken, "rsession": user_token, "finAppId": FINAPP_ID}
    r2 = requests.post(REST_URL + 'authenticator/token', data=data)
    d2 = r2.json()
    if "Error" in d2:
        raise ApiError(d2)
    auth_info = d2.get('finappAuthenticationInfos')
    token = auth_info.get("token") if isinstance(auth_info, dict) else auth_info[0].get("token")
    return token


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
