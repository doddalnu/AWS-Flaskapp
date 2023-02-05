from flask import Flask, render_template, url_for, redirect, session, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from flask_wtf.file import FileField
from werkzeug.utils import secure_filename
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
import os

app = Flask(__name__)
app.app_context().push()

print('File name : ', os.path.basename(__file__))
print('Directory Name:   ', os.path.dirname(__file__))
absolute_path = os.path.dirname(__file__)
db_path = 'sqlite:///'+ absolute_path +'/database.db' 


bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = db_path
app.config['SECRET_KEY'] = '164338448224212866796679500138822656752'
db = SQLAlchemy(app)


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    firstname = db.Column(db.String(20), nullable=False)
    lastname = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(20), nullable=False)
    password = db.Column(db.String(80), nullable=False)


class RegisterForm(FlaskForm):
    firstname = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Firstname"})

    lastname = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Lastname"})

    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    email = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Email"})


    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            raise ValidationError(
                'That username already exists. Please choose a different one.')


class LoginForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Login')


# class UploadForm(FlaskForm):
#     file = FileField()

# @app.route('/countwords', methods=['GET', 'POST'])
# @login_required
# def countwords():
#     form = UploadForm()
    
#     if form.validate_on_submit():
#         filename = secure_filename(form.file.data.filename)
#         file = request.files['file'].read().decode()
#         # form.file.data.save('uploads/' + filename)
#         print(file)
#         with open(filename, "r") as file1:
#             read_content = file1.read()
#             print(read_content)
#         return redirect(url_for('upload'))

#     return render_template('countwords.html', form=form)


@app.route('/')
@app.route('/home')
@app.route('/index')
def home():
    return render_template('home.html')


@app.route('/login', methods=['GET', 'POST'])
@app.route('/sign-in', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                # print(user.username)
                session['user'] = user.username
                return redirect(url_for('countwords'))
        else:
            return render_template('login.html', form=form, message="register first!")
    return render_template('login.html', form=form)


@app.route('/countwords', methods=['GET', 'POST'])
@login_required
def countwords():
    user = session['user']
    return render_template('countwords.html', user=user)


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@ app.route('/register', methods=['GET', 'POST'])
@app.route('/sign-up', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, firstname=form.firstname.data, lastname=form.lastname.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html', form=form)


if __name__ == "__main__":
    app.run(debug=True)