from flask import Flask
from flask.ext.login import LoginManager
from flask_oauth import OAuth
from flask.ext.sqlalchemy import SQLAlchemy
import os

ALLOWED_EXTENSIONS = set(['csv'])

app = Flask(__name__)
app.config.from_object('config')
db = SQLAlchemy(app)


app.secret_key = 'some_random_key'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'



from app.auth.views import auth
app.register_blueprint(auth)

db.create_all()
#from app.uploader.views import uploader
#app.register_blueprint(uploader)