## ITP DWD Fall 2012

## Flask and User Management

### Demo site to demonstrate how to 

* register and login users. 
* create database documents associated to a specific user.
* query database for documents by a user.


### To get started

* Download code
* Create Git repo

		git init
		git add .
		git commit -am "init commit"

* Create a virtual environment 

		virtualenv venv

* Install all requirements for app

		. runpip

	or 

		. venv/bin/activate
		pip install -r requirements.txt

* Create Heroku app

		heroku create

* Add MongoLab Starter Addon to your app
* Add MONGOLAB_URI from Heroku config to your .env file

		heroku config --shell | grep MONGOLAB_URI >> .env

### Create a SECRET_KEY for your .env and Heroku Config

We need a SECRET_KEY for salting the user passwords.

* Open your .env and add a new line 

	SECRET_KEY=SOMETHINGSECRETANDRANDOMHERE

* We need to add this secret key to Heroku config vars too

	heroku config:add SECRET_KEY=SOMETHINGSECRETANDRANDOMHERE

This will add a new key and value to the App on Heroku.


## Run it

With your MONGOLAB_URI and SECRET_KEY configured in .env and on Heroku config you should be good to run the code.

Run,

	. start

or 

	. venv/bin/activate
	foreman start




