from Banco.connect.connect import db
from flask_login import UserMixin
from sqlalchemy.sql import table, column, select, update, insert


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

    def __int__(self, nome, sobrenome, cpf, idade, email, password, saldo):
        self.nome = nome
        self.sobrenome = sobrenome
        self.cpf = cpf
        self.idade = idade
        self.email = email
        self.password = password

    def save_person(self):
        db.session.add(self)
        db.session.commit()

    def update_saldo_person(self, saldo, email):
        person = 'person'
        u = update(person)
        u = u.values({"saldo": f"{saldo}"})
        u = u.where('person'.email == f"{email}")
        db.session.execute(u)

    def is_active(self):
        return True

    def __repr__(self):
        return " "


db.create_all()
