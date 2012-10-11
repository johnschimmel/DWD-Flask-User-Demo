# -*- coding: utf-8 -*-
from flask.ext.mongoengine.wtf import model_form
from flask.ext.mongoengine import *
import datetime

    
class User(mongoengine.Document):
	email = mongoengine.EmailField(unique=True)
	password = mongoengine.StringField(default=True)
	active = mongoengine.BooleanField(default=True)
	isAdmin = mongoengine.BooleanField(default=False)
	timestamp = mongoengine.DateTimeField(default=datetime.datetime.now())
	

class Content(mongoengine.Document):
    user = mongoengine.ReferenceField('User') # ^^^ points to User model ^^^
    title = mongoengine.StringField()
    content = mongoengine.StringField()
    timestamp = mongoengine.DateTimeField(default=datetime.datetime.now())


# user form
user_form = model_form(User)

# content form
content_form = model_form(Content)
