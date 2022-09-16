from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
#from flask_uploads import IMAGES, UploadSet, configure_uploads
import os
from flask_login import LoginManager
from flask_migrate import Migrate
import pdfkit

basedir = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///devfruit.db'
app.config['SECRET_KEY'] = 'mysecretkey'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

migrate = Migrate(app, db)
with app.app_context():
    if db.engine.url.drivername=="sqlite":
        migrate.init_app(app, db, render_as_batch=True)
    else:
        migrate.init_app(app, db)


login_manager= LoginManager()
login_manager.init_app(app)
login_manager.login_view='clienteLogin'
login_manager.needs_refresh_message_category='danger'
login_manager.login_message= u"Realize o login"



'''
app.config['UPLOADED_PHOTOS_DEST'] = os.path.join(basedir,'static/images')
photos = UploadSet('photos',IMAGES)
configure_uploads(app, photos)
'''
from loja.admin import rotas
from loja.produtos import rotas
from loja.carrinho import carrinhos
from loja.cliente import rotas