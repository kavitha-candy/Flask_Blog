from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import data_required, length, email,equal_to, ValidationError
from flask_login import current_user
from flaskblog import bcrypt
from flaskblog.models import User


class RegistrationForm(FlaskForm):
    username=StringField('username',validators=[data_required(),length(min=5,max=10)])
    email =StringField('Email',validators=[data_required(),email()])
    password=PasswordField('password',validators=[data_required()])
    confirm_password = PasswordField('Confirm password', validators=[data_required(),equal_to('password')])
    submit = SubmitField ('sign up')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is taken. Please choose a different one!')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('That email is taken. Please choose a different one!')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[data_required(), email()])
    password = PasswordField('password',validators=[data_required()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

class UpdateAccountForm(FlaskForm):
    username = StringField('username', validators=[data_required(),length(min=5,max=10)])
    email = StringField('Email', validators=[data_required(),email()])
    picture = FileField('Update Profile Picture', validators=[FileAllowed(['jpg', 'jpeg'])])
    submit = SubmitField('Update')

    def validate_username(self, username):
        if username.data != current_user.username:
            user = User.query.filter_by(username=username.data).first()
            if user:
                raise ValidationError('That username is taken. Please choose a different one!')

    def validate_email(self, email):
        if email.data != current_user.email:
            user = User.query.filter_by(email=email.data).first()
            if user:
                raise ValidationError('That email is taken. Please choose a different one!')



class pwd_updateForm(FlaskForm):
    password = PasswordField('password', validators=[data_required()])
    submit = SubmitField('Check')

    def validate_password(self, password):
        if bcrypt.check_password_hash(current_user.password, password.data):
            return True
        else:
            raise ValidationError('You cannot change your password', 'success')

class pwd_changeForm(FlaskForm):
    password = PasswordField('password', validators=[data_required()])
    confirm_password = PasswordField('Confirm password', validators=[data_required(), equal_to('password')])
    submit = SubmitField('Reset')

class RequestResetForm(FlaskForm):
    email = StringField('Email', validators=[data_required(), email()])
    submit = SubmitField('Request Password Reset')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is None:
            raise ValidationError('There is no account with that email.  You must register first.')


class ResetPasswordForm(FlaskForm):
    password = PasswordField('password', validators=[data_required()])
    confirm_password = PasswordField('Confirm password', validators=[data_required(), equal_to('password')])
    submit = SubmitField('Reset Password')
