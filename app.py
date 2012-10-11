# -*- encoding: utf-8 -*-
import os
import re
import datetime

from flask import Flask, session, request, url_for, escape, render_template, json, jsonify, flash, redirect, abort
from werkzeug.security import generate_password_hash, check_password_hash
from flask.ext.login import (LoginManager, current_user, login_required,
                            login_user, logout_user, UserMixin, AnonymousUser,
                            confirm_login, fresh_login_required)
from flaskext.bcrypt import Bcrypt

from flask.ext.mongoengine import *

from forms import *
import models
from libs.user import *

app = Flask(__name__)
app.debug = True
app.secret_key = os.environ.get('SECRET_KEY')
flask_bcrypt = Bcrypt(app)

#mongolab connection
# uses .env file to get connection string
# using a remote db get connection string from heroku config
# using a local mongodb put this in .env
#       MONGOLAB_URI=mongodb://localhost:27017/dwdfall2012
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
	templateData = {
		'classnotes' : models.ClassNote.objects.order_by('+class_date')
	}

	return render_template('index.html', **templateData)
    #return 'Hello World!'

@app.route('/class/<url_title>')
def class_entry(url_title):

	entry = models.ClassNote.objects(url_title=url_title).first()

	if entry:
		templateData = {
			'entry' : entry
		}
		return render_template('entry.html', **templateData)
	
	else:
		# return with 404 page
		abort(404)

@app.route('/class/<url_title>/add_assignment', methods=['POST'])
def api_addassignment(url_title):
	
	honeypot = request.form.get('email')
	
	if request.method == "POST" and honeypot is None:
		entry = models.ClassNote.objects(url_title=url_title).first()
		
		if entry:

			entryData = {
				'name' : request.form.get('name',''),
				'url' : request.form.get('url',''),
				'description' : request.form.get('description','')	
			}

			print "received assignment"
			print entryData
			
			if entryData['name'] != '' and entryData['url'] != '' and entryData['description'] != '':
				assignment = models.Assignment(**entryData)
				entry.assignments.append(assignment)
				entryData['status'] = 'OK'

			else:
				
				entryData = { 'status' : 'ERROR' }

			try:
				entry.save()
				return jsonify(**entryData)
				

			except ValidationError:
				app.logger.error(ValidationError.errors)
				return "error on saving document"
		else:
			abort(500)

	else:
		# no GET on this route
		abort(404)
	
@app.route('/page/<pageid>')
def page(pageid):

	return render_template('pages/'+pageid+'.html')

@app.route('/styleguide')
def style_guide():
	return render_template('style_guide.html')

#
# Route disabled - enable route to allow user registration.
#
# @app.route("/register", methods=["GET","POST"])
# def register():
# 	registerForm = RegisterForm(csrf_enabled=True)

# 	if request.method == 'POST' and registerForm.validate():
# 		email = request.form['email']
		
# 		# generate password hash
# 		password_hash = flask_bcrypt.generate_password_hash(request.form['password'])
		
# 		# prepare User
# 		user = User(email,password_hash)
# 		print user

# 		try:
# 			user.save()
# 			if login_user(user, remember="no"):
# 				flash("Logged in!")
# 				return redirect(request.args.get("next") or url_for("index"))
# 			else:
# 				flash("unable to log you in")

# 		except:
# 			flash("unable to register with that email address")
# 			app.logger.error("Error on registration - possible duplicate emails")
	
# 	# prepare registration form			
# 	registerForm = RegisterForm(csrf_enabled=True)
# 	templateData = {

# 		'form' : registerForm
# 	}

# 	return render_template("/auth/register.html", **templateData)

@app.route('/admin', methods=["GET"])
@login_required
def admin_main():

	entries = models.ClassNote.objects().order_by('+class_date')
	
	templateData = {
		'entries' : entries
	}	

	return render_template('/admin/index.html', **templateData)
	

@app.route('/admin/entry', methods=["GET","POST"])
@login_required
def admin_create_entry():
	if request.method == "POST":

		entryData = {
			'title' : request.form.get('title',''),
			'url_title' : request.form.get('url_title',''),
			'description' : request.form.get('description',''),
			'published' : True if request.form['published'] == "true" else False,
			'github_url' : request.form.get('github_url',None),
			'demo_url' : request.form.get('demo_url',None),
			'content' : request.form.get('content'),
			'assignment' : request.form.get('assignment'),
			'class_date' : datetime.datetime.strptime(request.form.get('class_date'), "%Y-%m-%d")
		}
		
		entry = models.ClassNote(**entryData)
		
		try:
			entry.save()
			flash('Class entry:<b>%s</b> was saved' % entry.title)
			return redirect('/admin')

		except ValidationError:
			app.logger.error(ValidationError.errors)
			return "error on saving document"
		

	return render_template('/admin/entry_new.html')


@app.route("/admin/entry/edit/<entry_id>", methods=["GET","POST"])
@login_required
def admin_entry_edit(entry_id):
	# get single document returned
	entry = models.ClassNote.objects().with_id(entry_id)
	if entry:
		if request.method == "POST":
			entry.title = request.form.get('title','')
			entry.url_title = request.form.get('url_title','')
			entry.description = request.form.get('description','')
			entry.published = True if request.form['published'] == "true" else False
			entry.github_url = request.form.get('github_url',None)
			entry.demo_url = request.form.get('demo_url',None)
			entry.content = request.form.get('content')
			entry.assignment = request.form.get('assignment')
			entry.class_date = datetime.datetime.strptime(request.form.get('class_date'), "%Y-%m-%d")
			
			entry.save()

		
		return render_template('/admin/entry_edit.html', entry=entry)

	else:
		return "Unable to find entry %s" % entry_id		

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
