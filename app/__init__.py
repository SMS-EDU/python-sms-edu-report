from flask import Flask
from flask.ext.login import LoginManager
from flask_oauth import OAuth
from flask.ext.sqlalchemy import SQLAlchemy
import os

ALLOWED_EXTENSIONS = set(['csv'])

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/test.db'
app.config['WTF_CSRF_SECRET_KEY'] = 'random key for form'
db = SQLAlchemy(app)


app.secret_key = 'some_random_key'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'



oauth = OAuth()



google = oauth.remote_app('google',
    base_url='https://www.google.com/accounts/',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    request_token_url=None,
    request_token_params={
        'scope': 'https://www.googleapis.com/auth/userinfo.email',
        'response_type': 'code'
    },
    access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_method='POST',
    access_token_params={'grant_type': 'authorization_code'},
    consumer_key='',
    consumer_secret=''
)


from app.auth.views import auth
app.register_blueprint(auth)

#from app.uploader.views import uploader
#app.register_blueprint(uploader)