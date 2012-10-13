# -*- coding: utf-8 -*-
from flask.ext.mongoengine.wtf import model_form
from wtforms.fields import *
from flask.ext.mongoengine.wtf.orm import validators
from flask.ext.mongoengine import *
import datetime

    
class User(mongoengine.Document):
	email = mongoengine.EmailField(unique=True, required=True)
	password = mongoengine.StringField(default=True,required=True)
	active = mongoengine.BooleanField(default=True)
	isAdmin = mongoengine.BooleanField(default=False)
	timestamp = mongoengine.DateTimeField(default=datetime.datetime.now())
	

class Content(mongoengine.Document):
    user = mongoengine.ReferenceField('User', dbref=True) # ^^^ points to User model ^^^
    title = mongoengine.StringField()
    content = mongoengine.StringField()
    timestamp = mongoengine.DateTimeField(default=datetime.datetime.now())


user_form = model_form(User, exclude=['password'])

#register form
class SignupForm(user_form):
	password = PasswordField('Password', validators=[validators.Required(), validators.EqualTo('confirm', message='Passwords must match')])
	confirm = PasswordField('Repeat Password')


# content form
content_form = model_form(Content)
