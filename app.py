from flask import Flask, request

import mongoengine as engine
from flask_cors import CORS, cross_origin
import os
from flask_jwt_extended import JWTManager
from flask_mail import Mail
from datetime import timedelta
from flask_bcrypt import Bcrypt

from routes.auth import router as auth_router
from routes.shorten import router as shorten_router

app = Flask(__name__)

app.config['DEBUG'] = True
app.config["JWT_SECRET_KEY"] = os.getenv('JWT_SECRET_KEY')
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=48)

app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['MAIL_SERVER'] = "smtp.zoho.com"
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
#app.config['MAIL_DEBUG'] = True
app.config['MAIL_USERNAME'] = os.getenv('ADMIN_EMAIL')
app.config['MAIL_PASSWORD'] = os.getenv('ADMIN_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('ADMIN_EMAIL')

bcrypt = Bcrypt(app)
CORS(app)
jwt = JWTManager(app)
mail = Mail(app)


if False:#os.environ['ENV'] == 'prod':
    try:
        engine.connect(host=os.getenv('MONGO_URL'), db="shorta", ssl=True,ssl_cert_reqs='CERT_NONE')
    except Exception as e:
        print(e)
else:
    engine.connect(host=os.getenv('MONGO_URL_LOCAL'), db="shorta")

app.register_blueprint(auth_router)
app.register_blueprint(shorten_router)

if __name__ == '__main__':
    app.run(debug=True)