from flask import Blueprint, request
from models.url import URL
from models.user import User
import string, jwt, os
from random import choices
from datetime import datetime
from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity, jwt_required

router = Blueprint('shorten', __name__)

def gen_id(N):

    none = None
    ran_id = str(''.join(choices(string.ascii_lowercase + string.digits, k = N)))
    id_exists = URL.objects(alias=ran_id).first()
    if id_exists:
        gen_id(N)
    else:
        return ran_id
        
def validate(request):
    token = request.headers['Authorization'].split(' ')[1]
    info = jwt.decode(token, os.getenv('JWT_SECRET_KEY'), algorithms=['HS256'])
    return info

@router.post('/shorten')
def shrten():
    form = request.form
    verify_jwt_in_request()
    ident = get_jwt_identity()
    if 'url' in form:
        url = form['url']

        new_url = URL()
        new_url.url = url
        alias= gen_id(6)
        new_url.alias = alias

        time = datetime.time(datetime.now())
        date = datetime.date(datetime.now())
        new_url.date_created = f"{date} {time}"
        new_url.last_modified = f"{date} {time}"
        new_url.save()

        if ident:
            user = User.objects(email=ident).first()
            if user:
                user.urls.append(alias)
                user.save()
        return {'alias' : alias}
    else:
        return {'msg' : 'No URL provided'}, 400

@router.get('/fullurl')
def fullurl():

    args = request.args
    if 'alias' in args:

        alias = args['alias']
        url = URL.objects(alias=alias).first()

        if url:
            return {'url' : url.url}
        else:
            return 'URL not found', 404
    else:
        return {'msg' : 'No alias provided'}, 400

@router.post('/url/<alias>/click')
def click(alias):
    url = URL.objects(alias=alias).first()
    if url:
        url.clicks += 1
        url.save()
        return 'URL clicked'
    else:
        return 'URL not found', 404


@router.post('/url/<alias>/modify')
@jwt_required()
def modify(alias):
    args = request.args

    email = validate(request)['sub']
    if 'act' in args:
        act = args['act']

        if act == 'delete':
            url = URL.objects(alias=alias).first();
            if url:

                user = User.objects(email=email).first()
                if alias in user.urls:
                    url.delete()
                    user.urls.remove(alias)
                    user.save()
                    return 'URL deleted'
                else:
                    return {'msg' : 'You don\'t have rights to delete this url'}
            else:
                return {'msg' : 'Url with alias: ' + alias + ' not found'}, 400