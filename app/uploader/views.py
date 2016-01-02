import requests
from flask import request, render_template, flash, redirect, url_for, \
    session, Blueprint, g

auth = Blueprint('auth', __name__)

@auth.route('/uploader')
def uploader():
    return render_template('uploader.html')