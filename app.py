from Banco.connect import app, db

from flask import json
from flask import render_template, request, redirect, url_for
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user, fresh_login_required
from flask_wtf import FlaskForm

from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import InputRequired, Length

from werkzeug.security import generate_password_hash, check_password_hash

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.refresh_view = 'login'
login_manager.needs_refresh_message = 'You need to login again'


class User(db.Document, UserMixin):
    username = db.StringField(unique=True)
    password = db.StringField()


@login_manager.user_loader
def load_user(user_id):
    user = User.objects(id=f"{user_id}").first()
    return user


class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=32)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Register')


class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=32)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})
    checkbox = BooleanField()
    submit = SubmitField('Login')


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            body_pwd = form.password.data
            body_user = form.username.data
            try:
                existing_user = User.objects(username=f"{body_user}").first()
            except ConnectionError:
                raise ConnectionError('Erro de Conexão.')
            if existing_user:
                return redirect(url_for('register'))
            bodypwd_hashed = generate_password_hash(body_pwd, method='pbkdf2:sha256')
            obj = {
                "username": f"{body_user}",
                "password": f"{bodypwd_hashed}"
            }
            new_user = User(**obj).save()
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
            body_user = form.username.data
            remember_me = form.checkbox.data
            try:
                verify_user = User.objects(username=f"{body_user}").first()
            except ConnectionError:
                raise ConnectionError('Erro de Conexão.')
            if verify_user is None:
                return redirect(url_for('login'))
            dumps_obj_user = json.dumps(verify_user)
            load_username = json.loads(dumps_obj_user)
            pwd_hash = load_username.get('password')
            check_pwd = check_password_hash(pwd_hash, body_pwd)
            if not check_pwd:
                return redirect(url_for('login'))
            if not remember_me:
                login_user(verify_user, remember=False)
            else:
                login_user(verify_user, remember=True)
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


@app.route('/test')
@fresh_login_required
def test():
    return render_template('test.html')


if __name__ == '__main__':
    app.run(debug=True)
