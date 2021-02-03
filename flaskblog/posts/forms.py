from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, TextAreaField
from wtforms.validators import data_required


class PostForm(FlaskForm):
    title = StringField('Title', validators=[data_required()])
    Content = TextAreaField('Content', validators=[data_required()])
    submit = SubmitField('Post')
