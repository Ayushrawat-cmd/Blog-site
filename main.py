from functools import wraps
from flask import Flask, render_template, redirect, request, url_for, flash, g, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from sqlalchemy import ForeignKey
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm,LoginForm, CommentForm
from flask_gravatar import Gravatar
from smtplib import SMTP
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
ckeditor = CKEditor(app)
Bootstrap(app)
login_manager = LoginManager()
##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

##login
login_manager.init_app(app)

## contacts
contact_username = "ayushrawat324@gmail.com"
contact_password = "odasuviasqetnfgt"
## user_loader callback

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

##admin only
def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return abort(403)
        if current_user.id == 1:
            return f(*args, **kwargs)
        else:
            return abort(403)
    return decorated_function


##CONFIGURE TABLES
# print(current_user.id)
class User(UserMixin, db.Model):
    __tablename__ = "Users"
    id = db.Column(db.Integer, primary_key = True)
    email = db.Column(db.String(250),nullable = False, unique = True )
    password = db.Column(db.String(250), nullable = False)
    name = db.Column(db.String(250), nullable = False)
    posts = relationship("BlogPost", back_populates = "author")
    comment = relationship("Comment", back_populates = "author")

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer,ForeignKey('Users.id'))
    author = relationship("User", back_populates= "posts")
    comment = relationship("Comment", back_populates= "post")
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text )
    author_id = db.Column(db.Integer,ForeignKey("Users.id"))
    author = relationship("User", back_populates="comment")
    post_id = db.Column(db.Integer, ForeignKey("blog_posts.id"))
    post = relationship("BlogPost", back_populates = "comment")


db.create_all()
# db.session.delete(Comment.query.get(1))
# db.session.delete(Comment.query.get(2))
db.session.commit()


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


@app.route('/register',methods=["GET","POST"])
def register():
    form = RegisterForm()
    if request.method=="POST":
        try:
            new_user = User(
                email = request.form.get("email"),
                password=  generate_password_hash(password=request.form.get("password"), method="pbkdf2:sha256",salt_length=8),
                name  = request.form.get("name")
            )
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for("get_all_posts"))
        except:
            flash("You have already signed up with this email! Try login instead.")
            return redirect("login")
    return render_template("register.html",form = form)


@app.route('/login',methods = ["GET", "POST"])
def login():
    form = LoginForm()
    if request.method == "GET":
        return render_template("login.html", form =form)
    email = request.form.get("email")
    password = request.form.get("password")
    user = User.query.filter_by(email=email).first()
    if not user:
        flash("This email does not exist, please try again!")
    elif not check_password_hash(pwhash=user.password, password=password):
        flash("Password incorrect, please try again!")
    elif(check_password_hash(pwhash=user.password, password=password)):
        login_user(user=user)
        return redirect(url_for('get_all_posts'))
    
    return redirect(url_for('login'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods = ["GET", "POST"])
def show_post(post_id):
    form = CommentForm()
    if request.method == "GET":
        requested_post = BlogPost.query.get(post_id)
        return render_template("post.html", post=requested_post, form = form, comments = Comment.query.filter_by(post_id = post_id), gravatar = Gravatar(app, size=100, rating='g', default='retro', force_default=False, force_lower=False, use_ssl=False, base_url=None))
    if current_user.is_authenticated:
        new_comment = Comment(
            text = request.form.get("comment"),
            author = current_user,
            post = BlogPost.query.get(post_id)
        )
        db.session.add(new_comment)
        db.session.commit()
        return redirect(url_for("show_post",post_id = post_id ))
    else:
        flash("You need to login or register to do comment")
        return redirect(url_for("login"))


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact", methods =["GET", "POST"])
def contact():
    if(request.method =="GET"):
        return render_template("contact.html", heading = "Contact me!")
    connection = SMTP("smtp.gmail.com",587)
    connection.starttls()
    connection.login(user=contact_username, password=contact_password)
    name = request.form.get("name")
    print(name)
    email = request.form.get("email")
    phn = request.form.get("phn")
    content = request.form.get("content")
    mail = f"Subject:This mail is from blog site\n\nName: {name}\nEmail: {email}\nPhone no. {phn}\nBody: {content}"
    connection.sendmail(from_addr=contact_username,to_addrs=contact_username,msg=mail)
    connection.close()
    return render_template("contact.html", heading = "Successfully sent the mail!")


@app.route("/new-post", methods=["GET","POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>")
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000)
