from flask_wtf.file import FileAllowed, FileField, FileRequired
from wtforms import Form, IntegerField,StringField,BooleanField, TextAreaField, FloatField, validators, DecimalField



class Addprodutos(Form):
    name = StringField('Nome:', [validators.DataRequired()]) 
    price = DecimalField('Preço:', [validators.DataRequired()])
    weight = FloatField('Peso em kg:', [validators.DataRequired()])
    discount = IntegerField('Desconto:', [validators.DataRequired()])
    stock = IntegerField('Estoque:', [validators.DataRequired()])
    description = TextAreaField('Descrição:', [validators.DataRequired()])
    image = FileField('Imagem:',validators=[FileAllowed(['jpg','png','gif','jpeg'])])
