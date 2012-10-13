# -*- encoding: utf-8 -*-
import os,sys
import re
import datetime

from flask import Flask, session, request, url_for, escape, render_template, json, jsonify, flash, redirect, abort
from werkzeug.security import generate_password_hash, check_password_hash
from flask.ext.login import (LoginManager, current_user, login_required,
                            login_user, logout_user, UserMixin, AnonymousUser,
                            confirm_login, fresh_login_required)
from flaskext.bcrypt import Bcrypt
from flask.ext.mongoengine import mongoengine
import models

from libs.user import *

app = Flask(__name__)
app.debug = True

app.secret_key = os.environ.get('SECRET_KEY') # SECRET_KEY=...... inside .env
flask_bcrypt = Bcrypt(app) # for salting our user passwords

#mongolab connection
# uses .env file to get connection string
# using a remote db get connection string from heroku config
# 	using a local mongodb put this in .env
#   MONGOLAB_URI=mongodb://localhost:27017/dwdfall2012
mongoengine.connect('dwdfall2012', host=os.environ.get('MONGOLAB_URI'))


login_manager = LoginManager()
login_manager.anonymous_user = Anonymous
login_manager.login_view = "login"
login_manager.login_message = u"Please log in to access this page."
login_manager.refresh_view = "reauth"

@login_manager.user_loader
def load_user(id):
	if id is None:
		redirect('/login')

	user = User()
	user.get_by_id(id)
	if user.is_active():
		return user
	else:
		return None

login_manager.setup_app(app)


@app.route('/')
def index():
	# get requested user's content
	user_content = models.Content.objects

	# prepare the template data dictionary
	templateData = {
		'current_user' : current_user,
		'user_content'  : user_content,
		'users' : models.User.objects()
	}
	
	app.logger.debug(current_user)

	return render_template('all_content.html', **templateData)



@app.route('/admin', methods=['GET','POST'])
@login_required
def admin_main():

	contentForm = models.content_form(request.form)

	if request.method=="POST" and contentForm.validate():
		app.logger.debug(request.form)
		
		newContent = models.Content()
		newContent.title = request.form.get('title')
		newContent.content = request.form.get('content')

		#link to current user
		newContent.user = current_user.get()

		try:
			newContent.save()

		except:
			e = sys.exc_info()
			app.logger.error(e)
			
		return redirect('/admin')

	else:
		templateData = {
			'allContent' : models.Content.objects(),
			'current_user' : current_user,
			'form' : contentForm
		}
	

	return render_template('admin.html', **templateData)
		
@app.route('/users/<username>')
def user(username):

	try:
		user = models.User.objects.get(username=username)

	except Exception:
		e = sys.exc_info()
		app.logger.error(e)
		abort(404)

	# get requested user's content
	user_content = models.Content.objects(user=user)

	# prepare the template data dictionary
	templateData = {
		'user' : user,
		'current_user' : current_user,
		'user_content'  : user_content,
		'users' : models.User.objects()
	}

	return render_template('user_content.html', **templateData)


#
# Route disabled/enable route to allow user registration.
#
@app.route("/register", methods=["GET","POST"])
def register():
	
	loginForm = models.LoginForm(None)
	registerForm = models.SignupForm(request.form)
	
	if request.method == 'POST' and registerForm.validate():
		email = request.form['email']
		username = request.form['username']

		# generate password hash
		password_hash = flask_bcrypt.generate_password_hash(request.form['password'])
		
		# prepare User
		user = User(username=username, email=email, password=password_hash)
		
		# save new user, but there might be exceptions (uniqueness of email and/or username)
		try:
			user.save()	
			if login_user(user, remember="no"):
				flash("Logged in!")
				return redirect(request.args.get("next") or '/')
			else:
				flash("unable to log you in")

		# got an error, most likely a uniqueness error
		except mongoengine.queryset.NotUniqueError:
			e = sys.exc_info()
			exception, error, obj = e
			
			app.logger.error(e)
			app.logger.error(error)
			app.logger.error(type(error))

			# uniqueness error was raised. tell user (via flash messaging) which error they need to fix.
			if str(error).find("email") > -1:			
				flash("Email submitted is already registered.")
	
			elif str(error).find("username") > -1:
				flash("Username is already registered. Pick another.")

			app.logger.error(error)	

	# prepare registration form			
	templateData = {
		'loginForm' : loginForm,
		'form' : registerForm
	}
	
	return render_template("/auth/register.html", **templateData)

	

@app.route("/login", methods=["GET", "POST"])
def login():

	# get the login and registration forms
	loginForm = models.LoginForm(request.form)
	regForm = models.SignupForm(None)

	# is user trying to log in?
	# 
	if request.method == "POST" and 'email' in request.form:
		email = request.form["email"]

		user = User().get_by_email_w_password(email)
		
		# if user in database and password hash match then log in.
	  	if user and flask_bcrypt.check_password_hash(user.password,request.form["password"]) and user.is_active():
			remember = request.form.get("remember", "no") == "yes"

			if login_user(user, remember=remember):
				flash("Logged in!")
				return redirect(request.args.get("next") or '/admin')
			else:

				flash("unable to log you in")
		

	else:

		templateData = {
			'loginForm' : loginForm,
			'form' : regForm
		}

		return render_template('/auth/register.html', **templateData)


	
	

@app.route("/reauth", methods=["GET", "POST"])
@login_required
def reauth():
    if request.method == "POST":
        confirm_login()
        flash(u"Reauthenticated.")
        return redirect(request.args.get("next") or url_for("index"))
    
    templateData = {}
    return render_template("/auth/reauth.html", **templateData)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out.")
    return redirect(url_for("index"))


def datetimeformat(value, format='%H:%M / %d-%m-%Y'):
    return value.strftime(format)


@app.errorhandler(404)
def page_not_found(error):
    return render_template('page_not_found.html'), 404

if __name__ == '__main__':
    # Bind to PORT if defined, otherwise default to 5000.
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
