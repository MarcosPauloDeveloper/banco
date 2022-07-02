from flask import Flask, render_template, request, url_for, redirect

from flask_sqlalchemy import SQLAlchemy

from Banco.models.person import Person

app = Flask(__name__)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:4132@localhost/bank'
db = SQLAlchemy(app)


@app.route('/dashboard')
def index():
    person = Person.query.all()
    return render_template('dashboard.html', person=person)


db.create_all()

if __name__ == '__main__':
    app.run(debug=True)
