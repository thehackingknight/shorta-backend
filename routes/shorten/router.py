from flask import request, Blueprint
from models.otp import OTP
from models.user import User
from random import *
import os, time, re, datetime, jwt, json
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
from flask_jwt_extended import create_access_token, create_refresh_token
from flask_jwt_extended import get_jwt_identity

from flask_jwt_extended import jwt_required, verify_jwt_in_request
from threading import Thread
router = Blueprint('auth',__name__)
bcrypt = Bcrypt()

def validate(request):
    token = request.headers['Authorization'].split(' ')[1]
    info = jwt.decode(token, os.getenv('JWT_SECRET_KEY'), algorithms=['HS256'])
    return info
def gen_code():

    codes = OTP.objects()
    _min = 100000
    _max = 999999
    code = randint(_min, _max - 1)
    def fun():
        code_exists = OTP.objects(code=code).first()

        if code_exists:
            gen_code()
        else:
            return code

    c = fun()
    return c


@router.route('/shorten', methods=['GET','POST'])
def shorten():
    if request.method == 'GET':
        return 'Shorten'

    elif request.method == 'POST':

        form = request.form
        if 'url' in form:
            return 'ok'
        else:
            return {'msg' : 'No url specified'}, 400

def gen_token(identity, time={'h' : 24}):
    
    k = list(time.keys())[0]
    v = list(time.values())[0]
    if k == 'h':
        token = create_access_token(identity=identity, expires_delta=datetime.timedelta(hours=v))

    elif k == 'm':
        token = create_access_token(identity=identity, expires_delta=datetime.timedelta(minutes=v))

    return token


def validate_email(email):
    regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    return True if re.match(regex, email) else False

@router.route('/auth/signup', methods=['POST'])
def signup():

    form = request.form
    try:
        username = form['username']
        email = form['email']
        password = form['pwd']
        
        existing_email = User.objects(email=email)
        existing_username = User.objects(username=username)
        hashed_pass = bcrypt.generate_password_hash(password)
       
        if existing_username:
            return {'message' : f'User with username {username} already exists!'}, 400
        if existing_email:
            return {'message' : f'User with email {email} already exists!'}, 400

        user = User()
        user.username = username
        user.email = email
        user.password = hashed_pass
        
        if not validate_email(email):
            return {'message' : f'Please enter a valid email address.'}, 400
        
        try:   

            identity = {'email' : email, 'username' : username,'password' : str(user.password)}
            
            token = gen_token(identity, {'m' : 5})
            r_token = create_refresh_token(identity)
            url = f'{os.getenv("CLIENT_URL")}/auth/confirm?token={token}'
            
            temp_token = OTP()
            temp_token.token = token

            

            otp = gen_code()
            temp_token.code = otp
            temp_token.save()

            def del_tkn():
                time.sleep(300)
                temp_token.delete()
                print('Code expred and deleted.')
            thread = Thread(target=del_tkn)
            thread.start()
            return {'token': token, 'OTP': otp, 'r_token' : r_token}
            return send_email(
                subject= "TunedBass validation email",
                 message = f"""
                 <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta http-equiv="X-UA-Compatible" content="IE=edge">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style type="text/css">


                    .TunedBass{{
                        font: medium/ 1.5  Arial,Helvetica,sans-serif !important;
                        margin: auto;
                        padding: 10px;
                        color: black;

                    }}





                    .btn {{
                        cursor: pointer;
                        display: inline-block;
                        min-height: 1em;
                        outline: 0;
                        border: none;
                        vertical-align: baseline;
                        background: #e0e1e2 none;
                        color: rgba(0,0,0,.6);
                        font-family: Lato,"Helvetica Neue",Arial,Helvetica,sans-serif;
                        margin: 0 .25em 0 0;
                        padding: .78571429em 1.5em;
                        text-transform: none;
                        text-shadow: none;
                        font-weight: 600;
                        line-height: 1em;
                        font-style: normal;
                        text-align: center;
                        text-decoration: none;
                        border-radius: .28571429rem;
                        box-shadow: inset 0 0 0 1px transparent,inset 0 0 0 0 rgba(34,36,38,.15);
                        -webkit-user-select: none;
                        -ms-user-select: none;
                        user-select: none;
                        transition: opacity .1s ease,background-color .1s ease,color .1s ease,box-shadow .1s ease,background .1s ease;
                        will-change: "";
                        -webkit-tap-highlight-color: transparent;
                    }}
                    .btn-primary {{
                        color: #fff !important;
                        background-color: #0d6efd !important;
                        border-color: #0d6efd !important;

                    }}
            </style>
        </head>
        <body>

            <div class="TunedBass">

            <h1>Thank you for signing up to TunedBass!</h1>
               
            <p>Here is your OTP:</p>
            <p>Do not share this OTP with anyone!</p>
            <p style="text-align: center; color: rgb(223, 101, 1);font-size: 25px;font-weight: bold;letter-spacing: 2.5px">{temp_token.code}</p>
            <h3>The OTP is valid only for 5 minutes.</h3>
            
            <p>For support please contact us at <a href="mailto:admin@tunedbass.com">admin@tunedbass.com</a></p>
            </div>

        </body>
        </html>
                 """ ,
                  recipients=[email],
                   res={'token': token})

        except Exception as e:
            print(e)
            return {'msg' : 'Something went wrong'}, 500
    except Exception as e:
            print(e)
            return 'Something went wrong', 500

@router.post('/auth/code/reset')
def reset_code():
    token = request.form.get('tkn');
    r_token = request.form.get('r_tkn');
    #temp_token = TempToken.objects(token=token).first();
    temp_token = OTP()
    if True:
        info = jwt.decode(r_token, os.getenv('JWT_SECRET_KEY'), algorithms=['HS256'])
        identity = info['sub']
        token = gen_token(identity, {'m' : 5})
        otp = gen_code()

        temp_token.token = token
        temp_token.code = otp
        temp_token.save()

        def del_code():
            time.sleep(300)
            temp_token.delete()
            print('Code expired')

        thread  = Thread(target=del_code)
        thread.start()

        return {'token': token, 'OTP': otp}
        return send_email(
                    subject= "TunedBass validation email",
                     message = f"""
                     <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta http-equiv="X-UA-Compatible" content="IE=edge">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <style type="text/css">


                        .TunedBass{{
                            font: medium/ 1.5  Arial,Helvetica,sans-serif !important;
                            margin: auto;
                            padding: 10px;
                            color: black;

                        }}





                        .btn {{
                            cursor: pointer;
                            display: inline-block;
                            min-height: 1em;
                            outline: 0;
                            border: none;
                            vertical-align: baseline;
                            background: #e0e1e2 none;
                            color: rgba(0,0,0,.6);
                            font-family: Lato,"Helvetica Neue",Arial,Helvetica,sans-serif;
                            margin: 0 .25em 0 0;
                            padding: .78571429em 1.5em;
                            text-transform: none;
                            text-shadow: none;
                            font-weight: 600;
                            line-height: 1em;
                            font-style: normal;
                            text-align: center;
                            text-decoration: none;
                            border-radius: .28571429rem;
                            box-shadow: inset 0 0 0 1px transparent,inset 0 0 0 0 rgba(34,36,38,.15);
                            -webkit-user-select: none;
                            -ms-user-select: none;
                            user-select: none;
                            transition: opacity .1s ease,background-color .1s ease,color .1s ease,box-shadow .1s ease,background .1s ease;
                            will-change: "";
                            -webkit-tap-highlight-color: transparent;
                        }}
                        .btn-primary {{
                            color: #fff !important;
                            background-color: #0d6efd !important;
                            border-color: #0d6efd !important;

                        }}
                </style>
            </head>
            <body>

                <div class="TunedBass">

                <h1>Thank you for signing up to TunedBass!</h1>

                <p>Here is your OTP:</p>
                <p>Do not share this OTP with anyone!</p>
                <p style="text-align: center; color: rgb(223, 101, 1);font-size: 25px;font-weight: bold;letter-spacing: 2.5px">{temp_token.code}</p>
                <h3>The OTP is valid only for 5 minutes.</h3>

                <p>For support please contact us at <a href="mailto:admin@tunedbass.com">admin@tunedbass.com</a></p>
                </div>

            </body>
            </html>
                     """ ,
                      recipients=[email],
                       res={'token': token})

    else:
        return 'Invalid token', 400

@router.post('/auth/otp')
def otp():

    try:
        otp = request.form.get('OTP');
        token = request.form.get('tkn');

        tempTkn = OTP.objects(code=otp, token=token).first();
        if tempTkn:
            data = jwt.decode(tempTkn.token, os.getenv('JWT_SECRET_KEY'), algorithms=['HS256'])
            info = data['sub']
            email = info['email']
            user = User()
            for key, val in info.items():
                setattr(user, key, val)
            if True:
                user.is_verified = True
                user.save()

                user = user._data
                del user['password']
                user['id'] = str(user['id'])

                #delete token
                tempTkn.delete()
                return {'user' : user, 'token' : gen_token(user['email'], {'h' : 24})}
        else:
            return {'msg' : 'Invalid code'}, 400
        
        #print(OTP, token)
        return 'ok'
    except Exception as e:
        print(e)
        return {'msg' : 'Something went wrong'}, 500


@router.route('/auth/login', methods=['POST'])

def login():
    
    email = request.form.get('email')
    password = request.form.get('pwd')
    user = User.objects(email=email).first()

    if user:
        try:
            #print(user.password.split("'")[1])
            password_correct = bcrypt.check_password_hash(user.password.split("'")[1] , password)
        except Exception as e:
            print(e)
            return {'msg' : 'Som went wrong'}

        print(user.password)
        if password_correct:
            token = gen_token(email)
            
            data = user.to_json()
            return {'user' : json.loads(data), 'token' : token}
        else:
            return {"message" : "Incorrect Password"}, 400
    else:
        return {"message" : "User does not exist"}, 400

    return email
    
@router.post('/auth/getuser')
@jwt_required()


def get_user():
    email = validate(request)['sub']
    user = User.objects(email = email).first()
    token = request.headers['Authorization'].split(' ')[1]
    if user:
        return {'user' : user.to_json(), 'token': token}

    else:
        return 'invalid token', 400
  