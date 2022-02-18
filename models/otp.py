from mongoengine import *

class OTP(Document):
    code = IntField(max_length=6)
    token = StringField()

    def __str__():
        return code