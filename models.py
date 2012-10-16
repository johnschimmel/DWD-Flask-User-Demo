# -*- coding: utf-8 -*-
from flask.ext.mongoengine.wtf import model_form
from wtforms.fields import * # for our custom signup form
from flask.ext.mongoengine.wtf.orm import validators
from flask.ext.mongoengine import *
import datetime

    
class User(mongoengine.Document):
	username = mongoengine.StringField(unique=True, max_length=30, required=True, verbose_name="Pick a Username")
	email = mongoengine.EmailField(unique=True, required=True, verbose_name="Email Address")
	password = mongoengine.StringField(default=True,required=True)
	active = mongoengine.BooleanField(default=True)
	isAdmin = mongoengine.BooleanField(default=False)
	timestamp = mongoengine.DateTimeField(default=datetime.datetime.now())

user_form = model_form(User, exclude=['password'])

# signup form using WTForm directly
# provides additional password/confirm validation
class SignupForm(user_form):
	password = PasswordField('Password', validators=[validators.Required(), validators.EqualTo('confirm', message='Passwords must match')])
	confirm = PasswordField('Repeat Password')

class LoginForm(user_form):
	password = PasswordField('Password',validators=[validators.Required()])

#################  end of user models/forms ##########################


class Content(mongoengine.Document):
    user = mongoengine.ReferenceField('User', dbref=True) # ^^^ points to User model ^^^
    title = mongoengine.StringField(max_length="100",required=True)
    content = mongoengine.StringField(required=True)
    timestamp = mongoengine.DateTimeField(default=datetime.datetime.now())

    @mongoengine.queryset_manager
    def objects(doc_cls, queryset):
    	return queryset.order_by('-timestamp')

# content form
content_form = model_form(Content)
