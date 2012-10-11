from flaskext.wtf import Form, TextField, Required, PasswordField, validators, SelectField, EqualTo
from flaskext.wtf.html5 import EmailField
from flask import Flask, session

class RegisterForm(Form):
	email = EmailField('Email Address', validators=[], description="Enter your email address.")
	password = PasswordField('Password', validators=[Required(), EqualTo('confirm', message='Passwords must match')])
	confirm = PasswordField('Repeat Password')
	