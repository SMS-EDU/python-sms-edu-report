import requests
import os
from werkzeug import secure_filename
from app import ALLOWED_EXTENSIONS


            
from flask import request, render_template, flash, redirect, url_for, \
    session, Blueprint, g
from flask.ext.login import current_user, login_user, logout_user, \
    login_required
from app import login_manager, db
from config import google
from app.auth.models import User, FileForm

auth = Blueprint('auth', __name__)

GOOGLE_OAUTH2_USERINFO_URL = 'https://www.googleapis.com/oauth2/v1/userinfo'


def allowed_file(filename):
    return '.' in filename and \
            filename.lower().rsplit('.', 1)[1] in ALLOWED_EXTENSIONS


@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))


@auth.before_request
def get_current_user():
    g.user = current_user


@auth.route('/')
@auth.route('/home')
@auth.route('/login')
def home():
    return render_template('home.html')

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if g.user is not None and current_user.is_authenticated:
        flash('You are already logged in.', 'info')
        return redirect(url_for('home'))

    form = LoginForm(request.form)

    return render_template('login.html', form=form)
    
@auth.route('/google-login')
def google_login():
    return google.authorize(
        callback=url_for('auth.google_authorized', _external=True))


@auth.route('/oauth2callback')
@google.authorized_handler
def google_authorized(resp):
    if resp is None:
        return 'Access denied: reason=%s error=%s' % (
            request.args['error_reason'],
            request.args['error_description']
        )
    session['google_oauth_token'] = (resp['access_token'], '')
    userinfo = requests.get(GOOGLE_OAUTH2_USERINFO_URL, params=dict(
        access_token=resp['access_token'],
    )).json()
    
    
    url = 'http://localhost:9292/api/v1/uploader'
    email = userinfo['email']
    data = {'email':email}
    try:
        r = requests.get(url, data = data)
    except:
        flash('An error occured while processing your request. Please try again. If the problem persists contact the administrator', 'danger')
        return redirect(url_for('auth.home'))
    
        
    if email not in r.text:
        flash('You do not have permission to access. Please contact the administrator', 'danger')
        return redirect(url_for('auth.home'))

    user = User.query.filter_by(username=userinfo['email']).first()
    if not user:
        user = User(userinfo['email'], '')
        db.session.add(user)
        db.session.commit()

    login_user(user)
    flash(
        'Logged in as id=%s name=%s' % (userinfo['id'], userinfo['name']),
        'success'
    )
    return redirect(url_for('auth.uploader'))


@google.tokengetter
def get_google_oauth_token():
    return session.get('google_oauth_token')
    
@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.home'))
    



  
@auth.route('/uploader', methods=['GET','POST'])
@login_required
def uploader():
       
    form = FileForm(request.form)
    url = 'http://localhost:9292/api/v1/student_record'
    
    if form.validate_on_submit():
        file = request.files['file']
        record_type=form.record_type.data
        uploader_email = current_user.username
        data = {'uploader_email':uploader_email, 'record_type':record_type}
        if file and allowed_file(file.filename):
            files = {'file': file.stream}
            #filename = secure_filename(file.filename)
            r = requests.post(url, files=files, data=data)
            
            flash('File successfully uploaded','success')
        else:
            flash('No selected file/Unsupported file','danger')
    if form.errors:
        flash(form.errors, 'danger')     
    return render_template('uploader.html', form = form)
       
    
