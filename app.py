from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms.fields import BooleanField, PasswordField, EmailField, SubmitField, StringField, DecimalField
from wtforms.validators import InputRequired, Length
from werkzeug.security import generate_password_hash, check_password_hash

from models.person import Person

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.session_protection = "strong"
app = Flask(__name__)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:4132@localhost/bank'
app.secret_key = 'bank'
login_manager.init_app(app)

db = SQLAlchemy(app)


class LoginForm(FlaskForm):
    email = EmailField('Email', validators=[InputRequired(), Length(min=10, max=64)],
                       render_kw={"placeholder": "email"})
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=24)],
                             render_kw={"placeholder": "password"})
    cpf = StringField('CPF', validators=[InputRequired(), Length(max=11)],
                      render_kw={"placeholder": "cpf"})
    checkbox = BooleanField('Permanecer conectado')
    submit = SubmitField('Login')

class Forms(FlaskForm):
    valor_deposito = DecimalField('Valor', validators=[Length(min=10, max=1000000)], places=2, rounding=2,
                                render_kw={"placeholder": "Valor"})
    depositar = SubmitField('Depositar')

class RegisterForm(FlaskForm):
    email = EmailField('Email', validators=[InputRequired(), Length(min=10, max=64)],
                       render_kw={"placeholder": "email"})
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=24)],
                             render_kw={"placeholder": "password"})
    cpf = StringField('CPF', validators=[InputRequired(), Length(max=11)],
                      render_kw={"placeholder": "cpf"})
    idade = DecimalField('Idade', validators=[InputRequired()],
                         render_kw={"placeholder": "idade"})
    nome = StringField('Nome', validators=[InputRequired(), Length(min=3, max=32)],
                       render_kw={"placeholder": "nome"})
    sobrenome = StringField('Sobrenome', validators=[InputRequired(), Length(min=3, max=64)],
                            render_kw={"placeholder": "sobrenome"})
    submit = SubmitField('Registrar')


@login_manager.user_loader
def get_user(user_id):
    return Person.query.filter_by(id=user_id).first()


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            person = Person()
            body_pwd = form.password.data
            body_cpf = form.cpf.data
            body_email = form.email.data
            existing_cpf = Person.query.filter_by(cpf=body_cpf).first()
            existing_email = Person.query.filter_by(email=body_email).first()
            if existing_cpf or existing_email:
                flash("Usuário já existente")
                return redirect(url_for('register'))
            body_pwd_hashed = generate_password_hash(body_pwd, method='pbkdf2:sha256', salt_length=16)
            person.nome = form.nome.data
            person.sobrenome = form.sobrenome.data
            person.idade = form.idade.data
            person.password = body_pwd_hashed
            person.cpf = body_cpf
            person.email = body_email
            person.save_person()
            return redirect(url_for('login'))
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            body_pwd = form.password.data
            body_cpf = form.cpf.data
            body_email = form.email.data
            remember = form.checkbox.data
            existing_person = Person.query.filter_by(email=body_email, cpf=body_cpf).first()
            if not existing_person:
                return redirect(url_for('login'))
            if not check_password_hash(existing_person.password, body_pwd):
                return redirect(url_for('login'))
            verify_person = Person.query.filter_by(email=body_email).first()
            if not remember:
                login_user(verify_person, remember=False)
            else:
                login_user(verify_person, remember=True)
            ola = verify_person.nome
            session['nome'] = ola
            email_session = verify_person.email
            session['email'] = email_session
            return redirect(url_for('dashboard'))
    return render_template('login.html', form=form)


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    person_name = session["nome"]
    return render_template('dashboard.html', person=person_name)


@app.route('/depositar', methods=['GET', 'POST'])
@login_required
def depositar():
    form = Forms()
    pers = Person()
    email_id = session["email"]
    person = Person.query.filter_by(email=email_id).first()
    value = form.depositar.data
    pers.saldo = value
    pers.update_saldo_person(value, email_id)
    return render_template('depositar.html', form=form)


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)
