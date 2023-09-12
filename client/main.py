
from flask import Flask, render_template, request,session
import os
import io
import numpy as np
import  base64, io
import requests,json
from flask import Flask, render_template, session
from flask import Flask, render_template, redirect, url_for
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

app = Flask(__name__)
app.config['SECRET_KEY'] = 'NOBODY-CAN-GUESS-THIS'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'

app.secret_key = os.urandom(24)

app.config["IMAGE_UPLOADS"] = "static/uploads"
app.config["ALLOWED_IMAGE_EXTENSIONS"] = ["JPEG", "JPG", "PNG", "GIF"]


Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20))
    email = db.Column(db.String(30), unique=True)
    password = db.Column(db.String(80))

db.create_all()
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=20)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=5, max=80)])
    remember = BooleanField('remember me')


class RegisterForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(message="Invalid Email"), Length(min=6, max=30)])
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=20)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=5, max=80)])



@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                session['user']=user.username
                return render_template('page1.html')
        return render_template('login.html', data={'msg':"Wrong username or Password"},form=form)

    return render_template('login.html', data={'msg':""}, form=form)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return render_template('page1.html')

    return render_template('signup.html', form=form)


@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', name=current_user.username)


@app.route('/logout')
@login_required
def logout():
    try:
        session.pop['user']
    except:
        pass
    logout_user()
    return redirect(url_for(''))








@app.route("/")
def page1():
    session.clear()
    return render_template("page1.html")

@app.route("/imaging")

def home():
    try:
        session['user']
        return render_template("index.html")
    except:
        return redirect(url_for('login'))
@app.route("/result", methods=['POST','GET'])
def result():
    if request.method == 'POST':
        #global data
        session.clear()
        photo = request.files.get('file')
        photo = base64.b64encode(photo.read())
        photo = photo.decode('utf-8')
        data = {"img": photo}
        data=json.dumps(data)
        r = requests.post(url='http://127.0.0.1:5000/', data=data)

        res =r.text
        data={"data":res}

        session['data']=data


        return render_template('page2.html', data=data)
    else:
        return render_template('page2.html')

@app.route("/page2")
def page2():
    print(session['data'])
    return render_template("page2.html")

@app.route("/page3")
def page3():

    try:
        return render_template("page3.html", data=session['data'])
    except Exception as e:
        data={"data":'You have an Exception {0}'.format(e)}
        return render_template("page3.html", data=data)

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8181,debug=True)
