# WIKI webpage
# main.py

import hashlib
import hmac
import random
from string import letters
import re
import time
import jinja2
import webapp2
import os
from google.appengine.ext import db
from google.appengine.api import memcache

template_dir = os.path.join(os.path.dirname(__file__), 'templates')

jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape=False)

secret = 'secret'

class WikiEntries(db.Model):
    """
    Database for wiki entries.  Contains url and content
    """
    url = db.StringProperty(required = True)
    wiki = db.TextProperty()
    created = db.DateTimeProperty(auto_now_add = True)
    modified = db.DateTimeProperty()
    editedby = db.TextProperty()

class Users(db.Model):
    """
    User databse
    """
    user = db.StringProperty(required = True)
    password = db.StringProperty(required = True)
    email = db.StringProperty()

class Handler(webapp2.RequestHandler):
    """
    Handles webpage rendering
    """
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_cookie(self, name, value):
        cookie_val = make_secure_val(value)
        self.response.headers.add_header('Set-Cookie',
                '%s=%s; Path=/' % (str(name), str(cookie_val)))

    def get_cookie(self, user):
        cookie_val = self.request.cookies.get(user)
        return cookie_val and check_secure_val(cookie_val)
    
    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        user = self.get_cookie('name')
        self.user = user

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

def make_secure_val(user):
    return '%s|%s' % (user, hmac.new(secret, user).hexdigest())

def get_wiki(url):
    """
    Grab wiki and url
    """
    q = WikiEntries.all()
    q.filter('url =', url)
    wiki = q.order('-created').get()
    # initialize.  If webpage visited first time ever
    if url == '/' and not wiki:
        content = "Welcome to a pointless wiki"
        q = WikiEntries(wiki = content, url = url)
        q.put()
    # Wiki entry is found
    if wiki:
        content = wiki.wiki
    # url does not have a wiki
    else:
        content = None 
    return content

class MainPage(Handler):
    """
    Main page of the wiki.  Contains welcom message
    """
    def get(self, url):
        # using cookie for referral url
        self.set_cookie('current', url)

        content = get_wiki(url)
        # Nothing found in the database of /.... (url)
        if not content:
            print "inside not content"
            # if not logged in redirects to mainpage 
            # else redirect to editpage
            if not self.user:
                self.redirect('/')
            elif self.user:
                self.redirect('/_edit%s' % url)
        elif content:
            print "inside content"
            params = dict(content = content,
                          url = url)
            if not self.user:
                params['user'] = None
            elif self.user:
                params['user'] = self.user
            self.render('main.html', **params)
            
class EditPage(Handler):
    """
    Edit page.  Allows html
    """
    def get(self, url):
        #user = self.get_cookie('name')
        self.set_cookie('current', url)
        content = get_wiki(url)
        params = dict(content = content,
                      url = url,
                      user = self.user)
        if not self.user and not content:
            print 'just before redirect'
            self.redirect('/')
        elif self.user:
            self.render('edit.html', **params)

    def post(self, url):
        # get wii content
        content = self.request.get('text')

        # Put into database
        if content:
            entry = WikiEntries(url = url,
                                wiki = content)
            entry.put()
            time.sleep(1)
        self.redirect(url)
                                

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

def user_exists(username):
    q = Users.all()
    user = q.filter('user =', username).get()
    if user:
        return True
    else:
        return False
    

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

# password hashing ----------------------------------------
def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

class SignUp(Handler):
    """
    Sign up page
    """
    def get(self):
        refer = self.request.headers.get('referer', '/')
        self.render('signup.html', refer = refer)

    def post(self):

        # sets redirect url
        refer = str(self.request.get('refer'))
        if not refer or refer.startswith('/login'):
            refer = '/'

        # signup process
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(ret_user = self.username,
                      ret_email = self.email)

        if not valid_username(self.username):
            params['user_error'] = "That's not a valid username."
            have_error = True
        elif user_exists(self.username):
            params['user_error'] = "Username already exists"
            have_error = True

        if not valid_password(self.password):
            params['password_error'] = "Not a valid password."
            have_error = True
        elif self.password != self.verify:
            params['verify_error'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['email_error'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup.html', **params)
        else:
            self.hashed_pw = make_pw_hash(self.username,
                                     self.password)
            new_user = Users(user = self.username,
                             password = self.hashed_pw,
                             email = self.email)
            new_user.put()
            self.set_cookie('name', self.username)
            self.redirect(refer)

class Login(Handler):
    """
    User login
    """
    def get(self):
        refer = self.request.headers.get('referer', '/')
        self.render('login.html', refer = refer)

    def post(self):

        # redirect url
        refer = str(self.request.get('refer'))
        if not refer or refer.startswith('/login'):
            refer = '/'

        # login process
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        params = dict(ret_user = self.username)

        q = Users.all()
        user_info = q.filter('user =', self.username).get()
        if user_info and valid_pw(self.username, 
                                  self.password, 
                                  user_info.password):
            self.set_cookie('name', self.username)
            self.redirect(refer)
        else:
            params['user_error'] = 'Wrong username or password'
            self.render('login.html', **params)

class Logout(Handler):
    """
    Logs out user
    """
    def get(self):
        # clears user cookie after loggin out
        self.response.headers.add_header('Set-Cookie', 'name=None; Path=/')

        # using cookie for redirect
        # sendto = self.get_cookie('current')
        
        # using headers for redirect
        refer = self.request.headers.get('referer', '/')
        self.redirect(refer)
  
PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'
application = webapp2.WSGIApplication([
    ('/signup', SignUp),
    ('/login', Login),
    ('/logout', Logout),
    ('/_edit' + PAGE_RE, EditPage),
    (PAGE_RE, MainPage),
], debug=True)
