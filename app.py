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

	content = models.Content()
	content.content = "wowza"
	content.save()
	
	return 'Hello World!'


#
# Route disabled - enable route to allow user registration.
#
@app.route("/register", methods=["GET","POST"])
def register():
	
	registerForm = models.SignupForm(request.form)
	
	if request.method == 'POST' and registerForm.validate():
		email = request.form['email']
		
		# generate password hash
		password_hash = flask_bcrypt.generate_password_hash(request.form['password'])
		
		# prepare User
		user = User(email=email,password=password_hash)
		
		try:
			user.save()	
			if login_user(user, remember="no"):
				flash("Logged in!")
				return redirect(request.args.get("next") or '/')
			else:
				flash("unable to log you in")

		except mongoengine.queryset.NotUniqueError:
			e = sys.exc_info()
			app.logger.error(e)
			#return e
			
	# prepare registration form			
	templateData = {

		'form' : registerForm
	}
	app.logger.debug(templateData)

	return render_template("/auth/register.html", **templateData)

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
			'data' : [],
			'form' : contentForm
		}

	return render_template('admin.html', **templateData)
		

	

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST" and "email" in request.form:
        email = request.form["email"]
        userObj = User()
        user = userObj.get_by_email_w_password(email)
     	if user and flask_bcrypt.check_password_hash(user.password,request.form["password"]) and user.is_active():
			remember = request.form.get("remember", "no") == "yes"

			if login_user(user, remember=remember):
				flash("Logged in!")
				return redirect(request.args.get("next") or url_for("index"))
			else:
				flash("unable to log you in")

    return render_template("/auth/login.html")


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
