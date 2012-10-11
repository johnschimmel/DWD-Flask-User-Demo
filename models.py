# -*- coding: utf-8 -*-
from flask.ext.mongoengine import *
import datetime

class Link(EmbeddedDocument):
	title = StringField()
	url = URLField()
	timestamp = DateTimeField(default=datetime.datetime.now())

class Assignment(EmbeddedDocument):
    name = StringField(required=True)
    description = StringField()
    url = StringField()
    github_url = StringField()
    timestamp = DateTimeField(default=datetime.datetime.now())
    


class ClassNote(Document):
    title = StringField(required=True,max_length=120)
    url_title = StringField(unique=True,required=True, max_length=120)
    description = StringField()
    class_date = DateTimeField()
    content = StringField()
    assignment = StringField()
    assignments = ListField( EmbeddedDocumentField(Assignment) )
    github_url = StringField(default=None)
    demo_url =  StringField(default=None)
    references = ListField( EmbeddedDocumentField(Link) )
    last_updated = DateTimeField(default=datetime.datetime.now())
    published = BooleanField(default=False)
    
class User(Document):
	email = EmailField(unique=True)
	password = StringField(default=True)
	active = BooleanField(default=True)
	isAdmin = BooleanField(default=False)
	timestamp = DateTimeField(default=datetime.datetime.now())
	

class Content(Document):
	document_id = StringField()
	content = DictField()
