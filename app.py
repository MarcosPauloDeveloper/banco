from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_login import LoginManager, login_user, login_required, logout_user
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms.fields import BooleanField, PasswordField, EmailField, SubmitField, StringField, DecimalField, FloatField,\
    SelectField
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
    valor_deposito = FloatField('Valor', validators=[InputRequired(), Length(min=2, max=6)],
                                render_kw={"placeholder": "Valor"})
    depositar = SubmitField('Depositar')
    valor_saque = FloatField('Valor', validators=[InputRequired(), Length(min=2, max=6)],
                             render_kw={"placeholder": "Valor"})
    sacar = SubmitField('Sacar')
    valor_pix = FloatField('Valor', validators=[InputRequired(), Length(min=1, max=6)],
                           render_kw={"placeholder": "Valor"})
    select_chave = SelectField('Tipo de Chave', choices=['CPF', 'Email'],
                               render_kw={"placeholder": "Tipo de chave"})
    chave = StringField('Chave', validators=[InputRequired(), Length(min=11, max=64)],
                        render_kw={"placeholder": "Chave"})
    transferir = SubmitField('Transferir')
    criar_chave = SubmitField('Criar chave PIX')


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
            person.chave_pix_email = 0
            person.chave_pix_cpf = 0
            person.saldo = 0
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
    person = Person()
    if request.method == 'POST':
        email_id = session["email"]
        person_id = Person.query.filter_by(email=email_id).first()
        value_add = form.valor_deposito.data
        current_value = person_id.saldo
        if value_add:
            value_updated = value_add + current_value
            person_id.saldo = value_updated
            person.update()
            flash(message=f"Valor de {value_add}R$ foi depositado com sucesso!", category='success')
        else:
            flash(message="Insira um número válido", category='warning')
            return redirect(url_for('depositar'))
    return render_template('depositar.html', form=form)


@app.route('/sacar', methods=['GET', 'POST'])
@login_required
def sacar():
    form = Forms()
    person = Person()
    if request.method == 'POST':
        email_id = session["email"]
        person_id = Person.query.filter_by(email=email_id).first()
        valor_saque = form.valor_saque.data
        current_value = person_id.saldo
        if valor_saque:
            value_updated = current_value - valor_saque
            if value_updated < 0:
                flash(message="Não foi possível realizar o saque, seu saldo é insuficiente.", category='danger')
                return redirect(url_for('sacar'))
            person_id.saldo = value_updated
            person.update()
            flash(message=f"Saque de {valor_saque}R$ realizado com sucesso!", category='success')
        else:
            flash(message="Insira um número válido", category='warning')
            return redirect(url_for('sacar'))
    return render_template('sacar.html', form=form)


@app.route('/criar-pix', methods=['GET', 'POST'])
@login_required
def cria_pix():
    form = Forms()
    person = Person()
    if request.method == 'POST':
        email_id = session["email"]
        person_id = Person.query.filter_by(email=email_id).first()
        chave_pix = form.select_chave.data
        if chave_pix == 'CPF':
            if person_id.chave_pix_cpf != 1:
                person_id.chave_pix_cpf = 1
                person.update()
                flash(message="Chave PIX criada com sucesso!", category='success')
            else:
                flash(message="Sua chave PIX para seu CPF já foi criada anteriormente", category='info')
                return redirect(url_for('cria_pix'))
        else:
            if person_id.chave_pix_email != 1:
                person_id.chave_pix_email = 1
                person.update()
                flash(message="Chave PIX criada com sucesso!", category='success')
            else:
                flash(message="Sua chave PIX para seu Email já foi criada anteriormente", category='info')
                return redirect(url_for('cria_pix'))
    return render_template('cria_pix.html', form=form)


@app.route('/pix', methods=['GET', 'POST'])
@login_required
def pix():
    form = Forms()
    person = Person()
    if request.method == 'POST':
        email_id = session["email"]
        person_remetente = Person.query.filter_by(email=email_id).first()
        person_remetente_cpf = person_remetente.cpf
        saldo_remetente = person_remetente.saldo
        valor_pix = form.valor_pix.data
        tipo_chave = form.select_chave.data
        chave_pix = form.chave.data
        if saldo_remetente - valor_pix < 0:
            flash(message="Saldo insuficiente", category='warning')
            return redirect(url_for('pix'))
        if valor_pix and valor_pix > 0:
            if tipo_chave == 'CPF':
                destinatario = Person.query.filter_by(cpf=chave_pix).first()
                if destinatario is None:
                    flash(message="Chave Inválida", category='danger')
                    return redirect(url_for('pix'))
                try:
                    if destinatario.cpf and person_remetente.cpf:
                        if destinatario.cpf == person_remetente.cpf:
                            flash(message="Operação Inválida", category='danger')
                            return redirect(url_for('pix'))
                except ValueError:
                    ValueError
                if destinatario and destinatario.chave_pix_cpf == 1:
                    valor_destinatario = destinatario.saldo
                    novo_saldo_destinatario = valor_pix + valor_destinatario
                    destinatario.saldo = novo_saldo_destinatario
                    novo_saldo_remetente = saldo_remetente - valor_pix
                    person_remetente.saldo = novo_saldo_remetente
                    person.update()
                    flash(message=f"PIX no valor de {valor_pix}R$ foi realizado com sucesso!", category='success')
                    return redirect(url_for('pix'))
                flash(message=f"Chave PIX inválida", category='danger')
                return redirect(url_for('pix'))
            else:
                destinatario = Person.query.filter_by(email=chave_pix).first()
                if destinatario is None:
                    flash(message="Chave inválida", category='danger')
                    return redirect(url_for('pix'))
                try:
                    if destinatario.email and person_remetente.email:
                        if destinatario.email == person_remetente.email:
                            flash(message="Operação Inválida", category='danger')
                            return redirect(url_for('pix'))
                except ValueError:
                    ValueError
                if destinatario and destinatario.chave_pix_email == 1:
                    valor_destinatario = destinatario.saldo
                    novo_saldo_destinatario = valor_pix + valor_destinatario
                    destinatario.saldo = novo_saldo_destinatario
                    novo_saldo_remetente = saldo_remetente - valor_pix
                    person_remetente.saldo = novo_saldo_remetente
                    person.update()
                    flash(message=f"PIX no valor de {valor_pix}R$ foi realizado com sucesso!", category='success')
                    return redirect(url_for('pix'))
                flash(message=f"Chave PIX inválida", category='danger')
                return redirect(url_for('pix'))
        else:
            flash(message="Insira um número válido", category='warning')
            return redirect(url_for('pix'))
    return render_template('pix.html', form=form)


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)
