from loja import db, login_manager
from datetime import datetime
from flask_login import UserMixin
import json

class JsonEcodedDict(db.TypeDecorator):
    impl = db.Text

    def process_bind_param(self,value,dialect):
        if value is None:
            return '{}'
        else:
            return json.dumps(value)

    def process_result_value(self,value,dialect):
        if value is None:
            return {}
        else:
            return json.loads(value)


@login_manager.user_loader
def user_carregar(user_id): 
    return Cliente.query.get(user_id)

class Cliente(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name= db.Column(db.String(70), unique=False)
    cpf= db.Column(db.Integer, nullable = False, unique=True)
    contact= db.Column(db.String(70), unique=False)
    email= db.Column(db.String(70), unique=False)
    password= db.Column(db.String(70), unique=False)
    confirm= db.Column(db.String(70), unique=False)
    state= db.Column(db.String(70), unique=False)
    city= db.Column(db.String(70), unique=False)
    address= db.Column(db.String(70), unique=False)
    cep= db.Column(db.String(70), unique=False)
    profile = db.Column(db.String(70), unique=False, default='profile.jpg')
    data_criado = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __repr__(self):
        return '<Cliente %r>' % self.name


class ClientePedido(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    notafiscal= db.Column(db.String(20), unique=True, nullable=False)
    status= db.Column(db.String(20), default='pendente', nullable = False)
    cliente_id= db.Column(db.Integer, unique=False, nullable=False)
    data_criado= db.Column(db.DateTime, default=datetime.now,nullable=False)
    pedido= db.Column(JsonEcodedDict)

    def __repr__(self):
        return '<ClientePedido %r>' % self.notafiscal


db.create_all()