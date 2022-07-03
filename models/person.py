from Banco.connect.connect import db
from flask_login import UserMixin


class Person(db.Model, UserMixin):
    __tablename__ = 'person'
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(86), nullable=False)
    sobrenome = db.Column(db.String(86), nullable=False)
    cpf = db.Column(db.String(11), nullable=False, unique=True)
    idade = db.Column(db.SmallInteger, nullable=False)
    email = db.Column(db.String(64), unique=True, index=True)
    password = db.Column(db.String(1024), nullable=False)
    saldo = db.Column(db.Float)
    chave_pix_cpf = db.Column(db.Boolean)
    chave_pix_email = db.Column(db.Boolean)

    def __int__(self, nome, sobrenome, cpf, idade, email, password, saldo, chave_pix_cpf, chave_pix_email):
        self.nome = nome
        self.sobrenome = sobrenome
        self.cpf = cpf
        self.idade = idade
        self.email = email
        self.password = password
        self.saldo = saldo
        self.chave_pix_cpf = chave_pix_cpf
        self.chave_pix_email = chave_pix_email

    def save_person(self):
        db.session.add(self)
        db.session.commit()

    def update(self):
        db.session.commit()


db.create_all()
