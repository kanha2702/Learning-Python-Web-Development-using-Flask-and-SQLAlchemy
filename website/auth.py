from flask import Blueprint, render_template,request,flash,redirect,url_for
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from flask_login import login_user, login_required, logout_user, current_user

auth=Blueprint('auth',__name__)

@auth.route('/login', methods=['GET','POST'])
def login():
    if request.method=="POST":
        email=request.form.get('email')
        password=request.form.get('password')

        user= User.query.filter_by(email=email).first()

        if user:
            if check_password_hash(user.password,password):
                flash('Logged in successfully! ',category='success')
                login_user(user, remember=True)
                return redirect(url_for('views.home'))
            else:
                flash('Incorrect password, try again.',category='error')
        else:
            flash('Email doesnot exist.', category='error')

    return render_template("login.html", user=current_user)

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))

@auth.route('/signup',methods=['GET','POST'])
def signup():
    if request.method =='POST':
        email=request.form.get("email")
        firstname=request.form.get("firstname")
        password=request.form.get('password')
        cpassword=request.form.get('cpassword')
        
        user=User.query.filter_by(email=email).first()
        if user:
            flash('Email already exists.', category='error')

        if len(email)<4:
            flash("Email must be greater than 4 charachters.", category="error")
        elif len(firstname)<2:
            flash("First Name must be greater than 7 charachters.", category="error")
        elif password!=cpassword:
            flash("Password Does not Match.", category="error")
        elif len(password)<7:
            flash("Password must be greater than 7 charachters.", category="error")
        else:
            new_user=User(email=email,first_name=firstname,password=generate_password_hash(password))
            db.session.add(new_user)
            db.session.commit()
            # login_user(user, remember=True)
            flash("Account Created", category="success")
            return redirect(url_for("views.home"))

    
    return render_template("signup.html", user=current_user)