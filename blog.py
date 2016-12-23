import os
import re
from string import letters
import webapp2
import jinja2
from google.appengine.ext import db
import hashlib
import hmac

SECRET = "hateyouman\/i"
#temp SECRET

template_dir = os.path.join(os.path.dirname(__file__), 'template')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                              autoescape = True)

##------- Blog Content Starts Here --------
    ##---Parents--
def blog_key(name = "default"):
    return db.Key.from_path('blog',name)
    ##---Post(Table)---

class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    author = db.StringProperty(required = True)
    last_modified = db.DateTimeProperty(auto_now = True)

#class Comments(db.Model):
#   author = db.StringProperty(required = True)
#    content = db.TextProperty(required = True)
#    post_id = 
#    created = db.DateTimeProperty(auto_now_add = True)
    
class User_db(db.Model):
    fname = db.StringProperty(required = True)
    lname = db.StringProperty(required = True)
    email = db.EmailProperty(required = True)
    username = db.StringProperty(required = True)
    password_hash = db.StringProperty(required =True)
    register_Date = db.DateTimeProperty(auto_now_add = True)
    
def make_secure_val(val):
    return "%s|%s" % (val, hmac.new(SECRET,val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))
    
    def set_secure_cookie(self,name,val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header('Set-Cookie', '%s=%s; Path=/' %(str(name),str(cookie_val)))
    
    def read_secure_cookie(self,name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)
    
    def login(self,user):
		self.set_secure_cookie('username',user.username)
		self.redirect("/welcome")
        
    def logged(self):
        return self.read_secure_cookie("username")
        
    
def hash_password(password):
        return hashlib.sha256(password + SECRET).hexdigest()
        


class MainPage(Handler):
    def get(self):
        posts = db.GqlQuery("SELECT * FROM Post ORDER BY created DESC LIMIT 10")
        self.render('index.html',posts = posts,user = self.logged())
class Welcome(Handler):
    def get(self):
        posts = db.GqlQuery("SELECT * FROM Post ORDER BY created DESC LIMIT 10")
        self.render('welcome.html',posts = posts,user = self.logged())
        

class PostPage(Handler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        self.render("post.html", post = post, user = self.logged())
class DeletePost(Handler):
    def get(self,post_id):
        key = db.Key.from_path('Post',int(post_id), parent=blog_key())
        post = db.get(key)
        author = self.logged()
        if not post:
            self.error(404)
            return
        else:
            self.render("post.html", post = post)
            if post.author == author:
                post.delete()
                self.redirect('/')
            else:
                self.redirect('/')
            
        


class NewPost(Handler):
    def get(self):
        if not self.logged():
            self.redirect("/")
        self.render("new.html", user = self.logged())
    def post(self):
        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            content = content.replace('\n','<br>')
            p = Post(parent = blog_key(), subject = subject, content = content, author = self.logged())
            p.put()
            self.redirect('/%s' % str(p.key().id()))
            
        
class Signup(Handler):
    def get(self):
        self.render("signup.html")
    def post(self):
        fname = self.request.get('fname')
        lname = self.request.get('lname')
        email = self.request.get('email')
        username = self.request.get('username')
        password = self.request.get('pass')
        cpass = self.request.get('cpass')
        if not fname and lname and email and username and password and cpass:
            error = " All fields are required"
            self.render("signup.html",error = error)
        elif not password == cpass:
            error = "Passwords do not match"
            self.render("signup.html",error = error)
        else: 
            if User_db.all().filter("email = ",email).get():
                error = "Email Already existing"
                self.render("signup.html",error = error )
            elif User_db.all().filter("username = ",username).get():
                error = "Username Already Taken"
                self.render("signup.html",error = error )
            else:
                password = hash_password(password)
                p = User_db(fname = fname, lname =lname, email = email,username = username, password_hash = password)
                p.put()
                self.redirect("/welcome")
class Login(Handler):
    def get(self):
        self.render("login.html")
    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        if not username and password:
            error = " Enter both password and username "
            self.render("login.html",error = error)
        else:
            user = User_db.all().filter("username = ",username).get()
            if not user:
                error = "User does not exsist !"
                self.render("login.html",error = error)
            else:
                password = hash_password(password)
                if user.password_hash != password:
                    error = "Password Incorrect !"
                    self.render("login.html",error = error)
                else:
                    self.login(user)
class Logout(Handler):
    def get(self):
        if self.logged():
            self.set_secure_cookie('username','')
            self.redirect("/login")
        else:
            self.redirect("/login")

        
                      
app = webapp2.WSGIApplication([('/(\d+)',PostPage),
                               ('/newpost',NewPost),
                               ('/delete/(\d+)',DeletePost),
                               ('/signup',Signup),
                               ('/login',Login),
                               ('/welcome',Welcome),
                               ('/logout',Logout),
                               ('/',MainPage)],
                              debug=True)
