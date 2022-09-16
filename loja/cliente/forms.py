from wtforms import Form, SubmitField, IntegerField, FloatField,StringField,TextAreaField,validators,PasswordField,ValidationError
from flask_wtf.file import FileField, FileRequired, FileAllowed
from flask_wtf import FlaskForm
from .models import Cliente


class ClienteForm(FlaskForm):
    name= StringField('Nome: ')
    cpf= IntegerField('CPF: ', [validators.DataRequired()])
    contact= StringField('Telefone: ', [validators.DataRequired()])
    email= StringField('Email: ', [validators.DataRequired()])
    password= PasswordField('Senha: ', [validators.DataRequired(),validators.EqualTo('confirm', message='As senhas não conferem')])
    confirm= PasswordField('Repita a senha: ', [validators.DataRequired()])
    state= StringField('Estado: ', [validators.DataRequired()])
    city= StringField('Cidade: ', [validators.DataRequired()])
    address= StringField('Endereço: ', [validators.DataRequired()])
    cep= StringField('CEP: ', [validators.DataRequired()])
    profile = FileField('Perfil',validators=[FileAllowed(['jpg','png','gif','jpeg'])])

    submit= SubmitField('Cadastrar')

    def validate_email(self, email):
        if Cliente.query.filter_by(email=email.data).first():
            raise ValidationError("Esse e-mail já foi utilizado.")

    def validate_cpf(self, cpf):
        if Cliente.query.filter_by(cpf=cpf.data).first():
            raise ValidationError("Esse CPF já foi utilizado.")


class ClienteLoginForm(FlaskForm):
    email= StringField('Email: ', [validators.DataRequired()])
    password= PasswordField('Senha: ', [validators.DataRequired()])
