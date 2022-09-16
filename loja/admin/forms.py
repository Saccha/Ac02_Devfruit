from wtforms import Form, BooleanField, StringField, PasswordField, validators

class RegistrationForm(Form):
    name = StringField('Nome', [validators.Length(min=4, max=25)])
    username = StringField('Usuario', [validators.Length(min=4, max=25)])
    email = StringField('Email', [validators.Length(min=6 , max=35),validators.Email()])
    password = PasswordField('Nova senha' , [
        validators.DataRequired(),
        validators.EqualTo('confirm', message = "Senhas não são iguais.")
    ])
    confirm = PasswordField('Repita a senha')

class LoginFormulario(Form):
    email = StringField('Email', [validators.Length(min=6 , max=35),validators.Email()])
    password = PasswordField('Senha' , [validators.DataRequired()])