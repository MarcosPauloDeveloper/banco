from Banco.app import db


class Person(db.Model):
    __tablename__ = 'person'
    person_id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(86), nullable=False)
    sobrenome = db.Column(db.String(86), nullable=False)
    cpf = db.Column(db.String(11), nullable=False, unique=True)
    idade = db.Column(db.SmallInteger, nullable=False)
    email = db.Column(db.String(64), unique=True, index=True)
    password = db.Column(db.String(24), nullable=False)
    saldo = db.Column(db.Float, nullable=False)

    def __int__(self, nome, sobrenome, cpf, idade, email, password, saldo):
        self.nome = nome
        self.sobrenome = sobrenome
        self.cpf = cpf
        self.idade = idade
        self.email = email
        self.password = password
        self.saldo = saldo

    def save_person(self):
        db.session.add(self)
        db.session.commit()

    @classmethod
    def find_person(cls, nome):
        person = cls.query.filter_by(nome=nome).first()
        if person:
            return person
        return None
