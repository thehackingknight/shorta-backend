from mongoengine import *

class User(Document):
    username = StringField(unique=True, required=True)
    email = EmailField(unique=True, required=True)
    password = StringField(required=True)
    first_name = StringField()
    last_name = StringField()

    urls = ListField()
    is_pro = BooleanField(default=False)