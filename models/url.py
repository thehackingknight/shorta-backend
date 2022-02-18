from mongoengine import *
from datetime import datetime
class URL(Document):
    alias = StringField(max_length=6)
    url = URLField()
    clicks = IntField(default=0,)
    date_created = StringField()
    last_modified = StringField()


    def __str__(self):
        return self.url