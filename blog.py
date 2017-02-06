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

#template_dir = os.path.join(os.path.dirname(__file__), 'template')
template_dir = 'template'
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                              autoescape = True)

##------- Blog Content Starts Here --------
    ##---Parents--
def blog_key(name = "default"):
    return db.Key.from_path('blog',name)
    ##---Post(Table)---

class Post(db.Model):
    # Post Database Model
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    author = db.StringProperty(required = True)
    last_modified = db.DateTimeProperty(auto_now = True)
    post_likes = db.IntegerProperty(required = True)

class Comments(db.Model):
    # Comment Database Model
    author = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

class Likes(db.Model):
    # Likes
    user_id = db.IntegerProperty(required = True)

class User_db(db.Model):
    # User Database Model
    fname = db.StringProperty(required = True)
    lname = db.StringProperty(required = True)
    email = db.EmailProperty(required = True)
    username = db.StringProperty(required = True)
    password_hash = db.StringProperty(required =True)
    register_Date = db.DateTimeProperty(auto_now_add = True)

def make_secure_val(val):
    # function to make a secure value to be stored in a cookie.
    return "%s|%s" % (val, hmac.new(SECRET,val).hexdigest())

def check_secure_val(secure_val):
    """
    check if the value and its secure version actually matches,
    if true it returns the value itself else False
    """

    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val
    else:
        return False


class Handler(webapp2.RequestHandler):
    """
        This is the Handler Class, inherits webapp2.RequestHandler,
        and provides helper methods.
    """
    def write(self, *a, **kw):
        # writes the output to client browser
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        # This methods returns html using template.
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        """
            this method combines render str and
            write returned html on client browser.
        """
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self,name,val):
        # Sets Secure Cookie on client browser
        cookie_val = make_secure_val(val)
        self.response.headers.add_header('Set-Cookie', '%s=%s; Path=/' %(str(name),str(cookie_val)))

    def read_secure_cookie(self,name):
        # Reads Secure Cookie from client browser
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self,user):
        """
            Sets the username of user Securely in the browser cookies,
            and redirect the user to welcome page
        """
        self.set_secure_cookie('username',user.username)
        self.redirect("/welcome")

    def logged(self):
        """
            check if the user is logged,
            if yes then return username of user
        """
        username = self.read_secure_cookie("username")
        if username:
            user = User_db.all().filter("username = ",username).get()
            if user:
                return username
            else:
                return False
        else:
            return False

    def liked(self,username,post_key):
        """
            Validates if user has alredy liked the post or not
            if liked then returns the like from Like table
            else return False
        """
        if username:
            user = db.GqlQuery("SELECT * FROM User_db WHERE username = :user", user = username )
            user_id = user.get().key().id()
            like = Likes.all()
            like.ancestor(post_key)
            like.filter("user_id = ",user_id)
            like = like.get()
            if like:
                return like
            else:
                return False
        else:
            return False


def hash_password(password):
    # Hash the password for storing it Securely in database.
    return hashlib.sha256(password + SECRET).hexdigest()



class MainPage(Handler):
    def get(self):
        # get request Handler for main index page
        posts = db.GqlQuery("SELECT * FROM Post ORDER BY created DESC LIMIT 10")
        self.render('front.html',posts = posts,user = self.logged())
class Welcome(Handler):
    def get(self):
        # get request Handler for main welcome page
        posts = db.GqlQuery("SELECT * FROM Post ORDER BY created DESC LIMIT 10")
        self.render('welcome.html',posts = posts,user = self.logged())


class PostPage(Handler):
    def get(self, post_id):
        # get request Handler for view post page
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if not post:
            # validation to check if post exsist
            self.error(404)
            return
        # loading all the comments from comment database using postifd as key
        comments = Comments.all()
        comments.ancestor(key)
        comments.order('last_modified')
        username = self.logged()
        like = self.liked(username,key)
        self.render("post.html", post = post, user = username, comments = comments,like = like)
    def post(self, post_id):
        # post request listning for new comments from post page
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if not post:
            # validation to check if post exsist
            self.error(404)
            return
        user = self.logged()
        content = self.request.get('comment')
        if user:
            # validation to check if user if logged in or not
            if content:
                # validation to checl if comment is empty or not
                content = content.replace('\n','<br>')
                comment = Comments(parent = key, author = user, content = content)
                comment.put()
                self.redirect('/%s' % str(post.key().id()))
            else:
                self.redirect('/%s?error=emptyCmnt' % str(post.key().id()))
        else:
            self.redirect('/%s?error="notLogged"' % str(post.key().id()))


class Like(Handler):
    def get(self,post_id):
        """
            validates the like action of user and
            reponds appropritly
        """
        key = db.Key.from_path('Post',int(post_id), parent=blog_key())
        post =db.get(key)
        if not post:
            # validates the post exsistence
            self.error(404)
            return
        user = self.logged()
        if user:
            # validates if the user is logged in or not
            like = self.liked(user,key)
            if not like:
                # check if user has not liked the post already
                user = db.GqlQuery("SELECT * FROM User_db WHERE username = :user", user = user )
                user = user.get()
                user_id = user.key().id()
                if post.author == self.logged():
                    # check if user is liking his/her own post
                    self.redirect("/%s?error=ownPost" % post_id)
                else:
                    new_like = Likes(parent = key,user_id = user_id)
                    new_like.put()
                    post.post_likes += 1
                    post.put()
                    self.redirect("/%s" % post_id)
            elif like:
                # check if user has already liked the post
                # this will then unlike the post
                like.delete()
                post.post_likes -= 1
                post.put()
                self.redirect("/%s" % post_id)
        else:
            self.redirect("/%s?error=notLogged" % post_id)



class DeletePost(Handler):
    """
        validates the delete action of user and
        reponds appropritly
    """
    def get(self,post_id):
        key = db.Key.from_path('Post',int(post_id), parent=blog_key())
        post = db.get(key)
        author = self.logged()
        if not post:
            # validates the post exsistence
            self.error(404)
            return
        else:
            self.render("post.html", post = post)
            if post.author == author:
                # check if user is deleting his/her own post
                post.delete()
                self.redirect('/')
            else:
                self.redirect('/%s?error=notPostOwner')




class NewPost(Handler):
    def get(self):
        """
            renders the page for new Post
        """
        if self.logged():
            # validates if user is logged in or not.
            self.render("new.html", user = self.logged())
        else:
            self.redirect("/login")
    def post(self):
        # request data for new post
        subject = self.request.get('subject')
        content = self.request.get('content')
        # validation for empty subject and content
        if subject and content:
            if self.logged():
                # validates if user is logged in or not.
                content = content.replace('\n','<br>')
                p = Post(parent = blog_key(), subject = subject, content = content, author = self.logged(), post_likes = 0)
                p.put()
                self.redirect('/%s' % str(p.key().id()))
            else:
                self.redirect("/login")
        else:
            self.render("new.html", user = self.logged(), error = "Fields Can't Be Enpty")



class EditPost(Handler):
    def get(self,post_id):
        """
            renders the page for edit Post
        """
        user = self.logged()
        if user:
            # validation for user log
            pkey = db.Key.from_path('Post',int(post_id), parent=blog_key())
            post = db.get(pkey)
            if not post:
                # validation for post exsistence
                self.error(404)
                return
            if user != post.author:
                # validation for post ownership
                self.redirect('/%s?error=notPostOwner' % post_id)
            else:
                self.render("edit.html", user = self.logged(), post = post)
        else:
            self.redirect("/login")

    def post(self,post_id):
        # request data for edit post
        subject = self.request.get('subject')
        content = self.request.get('content')
        user = self.logged()
        if subject and content:
            # validation for empty subject and content
            if user:
                # validation to check if user is logged in or not
                pkey = db.Key.from_path('Post',int(post_id), parent=blog_key())
                post = db.get(pkey)
                if not post:
                    # validates if post exsists
                    self.error(404)
                    return
                if user != post.author:
                    # validates if post ownership is same as of logged user
                    self.redirect('/%s?error=notPostOwner' % post_id)
                else:
                    # update the old data with new given data.
                    content = content.replace('\n','<br>')
                    post.content = content
                    post.subject = subject
                    post.put()
                    self.redirect('/%s' % post_id)
            else:
                self.redirect('/%s?error=notLogged' % pkey)
        else:
            self.render("new.html", user = self.logged(), error = "Fields Can't Be Enpty")



class DeleteComment(Handler):
    def get(self,post_id,comment_id):
        user = self.logged()
        if user:
            # validates if user is logged in or not.
            pkey = db.Key.from_path('Post',int(post_id), parent=blog_key())
            post = db.get(pkey)
            if not post:
                # validates the post exsistence
                self.error(404)
                return
            key = db.Key.from_path('Comments', int(comment_id), parent=pkey)
            comment = db.get(key)
            if user == comment.author:
                # Validates Comment Ownership
                comment.delete()
                self.redirect('/%s' % post_id )
            else:
                self.redirect('/%s?error=notCmntOwner' % post_id)
        else:
            self.redirect('/%s?error="notLogged"' % post_id)


class EditComment(Handler):
    def get(self,post_id,comment_id):
        user = self.logged()
        if user:
            # validates if user is logged in or not.
            pkey = db.Key.from_path('Post',int(post_id),parent=blog_key())
            post = db.get(pkey)
            if not post:
                # validates the post exsistence
                self.error(404)
                return
            key = db.Key.from_path('Comments',int(comment_id),parent = pkey)
            comment = db.get(key)
            if user == comment.author:
                # Validates Comment Ownership
                self.render('editcomment.html',user = user,comment = comment)
            else:
                self.redirect('/%s?error=notCmntOwner' % post_id)
    def post(self,post_id,comment_id):
        user = self.logged()
        if user:
            # validates if user is logged in or not.
            pkey = db.Key.from_path('Post',int(post_id),parent=blog_key())
            post = db.get(pkey)
            if not post:
                # validates the post exsistence
                self.error(404)
                return
            key = db.Key.from_path('Comments',int(comment_id),parent = pkey)
            comment = db.get(key)
            if user == comment.author:
                # Validates Comment Ownership
                content = self.request.get('comment')
                if content:
                    # Check if for empty comment
                    comment.content = content
                    comment.put()
                    self.redirect('/%s' % post_id)
                else:
                    self.redirect('/%s?error=emptyCmnt' % post_id)

            else:
                self.redirect('/%s?error=notCmntOwner' % post_id)




class Signup(Handler):
    def get(self):
        # renders the signup page
        self.render("signup.html")
    def post(self):
        # requests all the data required for new user
        fname = self.request.get('fname')
        lname = self.request.get('lname')
        email = self.request.get('email')
        username = self.request.get('username')
        password = self.request.get('pass')
        cpass = self.request.get('cpass')
        if not fname and lname and email and username and password and cpass:
            # validates if all the data is present and nothing is empty
            error = " All fields are required"
            self.render("signup.html",error = error)
        elif not password == cpass:
            # checks if password equals confirm password
            error = "Passwords do not match"
            self.render("signup.html",error = error)
        else:
            if User_db.all().filter("email = ",email).get():
                # check database for pre-exsisting email in database
                error = "Email Already existing"
                self.render("signup.html",error = error )
            elif User_db.all().filter("username = ",username).get():
                # check database for pre-exsisting username in database
                error = "Username Already Taken"
                self.render("signup.html",error = error )
            else:
                password = hash_password(password)
                #gets the hashed password to be stored in the db.
                p = User_db(fname = fname, lname =lname, email = email,username = username, password_hash = password)
                p.put()
                self.redirect("/welcome")


class Login(Handler):
    def get(self):
        # renders the login page
        self.render("login.html")
    def post(self):
        # request for username and password
        username = self.request.get('username')
        password = self.request.get('password')
        if not username and password:
            # validates if username or password are empty
            error = " Enter both password and username "
            self.render("login.html",error = error)
        else:
            user = User_db.all().filter("username = ",username).get()
            if not user:
                # validates if user exsists in db.
                error = "User does not exsist !"
                self.render("login.html",error = error)
            else:
                password = hash_password(password)
                if user.password_hash != password:
                    # Password validation
                    error = "Password Incorrect !"
                    self.render("login.html",error = error)
                else:
                    # Logins the user
                    self.login(user)


class Logout(Handler):
    def get(self):
        """
            Validates if user is alredy logged out or not
            if not then log him/her out
        """
        if self.logged():
            self.set_secure_cookie('username','')
            self.redirect("/login")
        else:
            self.redirect("/login")



app = webapp2.WSGIApplication([('/(\d+)',PostPage),
                               ('/newpost',NewPost),
                               ('/delete:(\d+)',DeletePost),
                               ('/edit:(\d+)',EditPost),
                               ('/signup',Signup),
                               ('/login',Login),
                               ('/welcome',Welcome),
                               ('/logout',Logout),
                               ('/editcomment:(\d+)&(\d+)',EditComment),
                               ('/deletecomment:(\d+)/(\d+)',DeleteComment),
                               ('/like:(\d+)',Like),
                               ('/?',MainPage)],
                              debug=True)
