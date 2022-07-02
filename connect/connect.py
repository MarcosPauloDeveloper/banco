from flask import Flask
from datetime import timedelta

from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:4132@localhost/bank'
app.config['REMEMBER_COOKIE_DURATION'] = timedelta(days=7)
app.secret_key = 'bank'

db = SQLAlchemy(app)
