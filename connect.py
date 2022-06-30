from flask import Flask
from flask_mongoengine import MongoEngine
from datetime import timedelta

app = Flask(__name__, template_folder='templates')
app.config['MONGODB_SETTINGS'] = {
    'db': 'Banco',
    'host': 'localhost',
    'port': 27017
}

app.config['SECRET_KEY'] = 'Banco'
app.config['REMEMBER_COOKIE_DURATION'] = timedelta(days=1)
app.secret_key = 'Banco'
db = MongoEngine(app)
