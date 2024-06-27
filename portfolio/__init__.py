from flask import Flask, render_template
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func
from flask_mail import Mail, Message


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///portfolio.db'
app.config['SECRET_KEY'] = 'b284c64b366d57f0f7b05bf0'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = "login_page"
login_manager.login_message_category = "info"

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'ratemybuilding0@gmail.com'
app.config['MAIL_PASSWORD'] = 'doon ilau uzwx fuoj'

mail = Mail(app)

from portfolio import routes

def delete_all_tables():
    with app.app_context():
        db.reflect()
        db.drop_all()

#Deletes all tables...Keep commented
#delete_all_tables()


with app.app_context():
    db.create_all()