from Banco.connect import app, db

from flask import json
from flask import render_template, request, redirect, url_for
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user
from flask_wtf import FlaskForm

from wtforms import StringField, PasswordField, SubmitField, BooleanField, IntegerField, EmailField
from wtforms.validators import InputRequired, Length

from werkzeug.security import generate_password_hash, check_password_hash


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.refresh_view = 'login'
login_manager.needs_refresh_message = 'You need to login again'


class Person(db.Document, UserMixin):
    nome = db.StringField()
    sobrenome = db.StringField()
    idade = db.IntField()
    cpf = db.StringField(unique=True)
    email = db.EmailField(unique=True)
    password = db.StringField()


@login_manager.user_loader
def load_user(user_id):
    person = Person.objects(id=f"{user_id}").first()
    return person


class RegisterForm(FlaskForm):
    nome = StringField(validators=[InputRequired(), Length(min=4, max=32)], render_kw={"placeholder": "nome"})
    sobrenome = StringField(validators=[InputRequired(), Length(min=4, max=32)], render_kw={"placeholder": "sobrenome"})
    idade = IntegerField(validators=[InputRequired()], render_kw={"placeholder": "idade"})
    cpf = StringField(validators=[InputRequired(), Length(min=11, max=14)], render_kw={"placeholder": "cpf"})
    email = EmailField(validators=[InputRequired(), Length(min=10, max=32)], render_kw={"placeholder": "email"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "password"})
    submit = SubmitField('Register')


class LoginForm(FlaskForm):
    cpf = StringField(validators=[InputRequired(), Length(max=14)], render_kw={"placeholder": "cpf"})
    email = EmailField(validators=[InputRequired(), Length(min=10, max=32)], render_kw={"placeholder": "email"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "password"})
    checkbox = BooleanField()
    submit = SubmitField('Login')


class Banco:

    @app.route('/register', methods=['GET', 'POST'])
    def register():
        a = 'l'
        form = RegisterForm()
        if request.method == 'POST':
            if form.validate_on_submit():
                body_pwd = form.password.data
                body_email = form.email.data
                body_cpf = form.cpf.data
                body_idade = form.idade.data
                body_nome = form.nome.data
                body_sobrenome = form.sobrenome.data
                try:
                    existing_user = Person.objects(email=f"{body_email}", cpf=f"{body_cpf}").first()
                except ConnectionError:
                    raise ConnectionError('Erro de Conexão.')
                if existing_user:
                    return redirect(url_for('register'))
                bodypwd_hashed = generate_password_hash(body_pwd, method='pbkdf2:sha256', salt_length=16)
                obj = {
                    "cpf": f"{body_cpf}",
                    "nome": f"{body_nome}",
                    "sobrenome": f"{body_sobrenome}",
                    "idade": f"{body_idade}",
                    "email": f"{body_email}",
                    "password": f"{bodypwd_hashed}"
                }
                new_user = Person(**obj).save()
                return redirect(url_for('login'))
        return render_template('register.html', form=form)

    @app.route('/')
    def home():
        return render_template('home.html')

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        form = LoginForm()
        if request.method == 'POST':
            if form.validate_on_submit():
                body_pwd = form.password.data
                body_email = form.email.data
                body_cpf = form.cpf.data
                remember_me = form.checkbox.data
                try:
                    verify_user = Person.objects(email=f"{body_email}", cpf=f"{body_cpf}").first()
                except ConnectionError:
                    raise ConnectionError('Erro de Conexão.')
                if verify_user is None:
                    return redirect(url_for('login'))
                dumps_obj_user = json.dumps(verify_user)
                load_username = json.loads(dumps_obj_user)
                pwd_hash = load_username.get('password')
                ola = load_username.get('nome')
                check_pwd = check_password_hash(pwd_hash, body_pwd)
                if not check_pwd:
                    return redirect(url_for('login'))
                if not remember_me:
                    login_user(verify_user, remember=False)
                else:
                    login_user(verify_user, remember=True)
                ola = load_username.get('nome')
                print(ola)
                return redirect(url_for('dashboard'))
        return render_template('login.html', form=form)

    @app.route('/dashboard', methods=['GET', 'POST'])
    @login_required
    def dashboard():
        return render_template('dashboard.html')

    @app.route('/logout', methods=['GET', 'POST'])
    @login_required
    def logout():
        logout_user()
        return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)
