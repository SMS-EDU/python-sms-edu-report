from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import Form
from wtforms import TextField, PasswordField, FileField, SelectField
from wtforms.validators import InputRequired, EqualTo
from app import db

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100))
    pwdhash = db.Column(db.String())
 
    def __init__(self, username, password):
        self.username = username
        self.pwdhash = generate_password_hash(password)
 
    def check_password(self, password):
        return check_password_hash(self.pwdhash, password)

    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return unicode(self.id)

class FileForm(Form):
    file = FileField('CSV File')
    record_type = SelectField ('Record Type', validators=[InputRequired()], choices=[('',''),('weekly_report', 'Weekly Report'),('report_card','Report Card')])