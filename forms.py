from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, EmailField, SubmitField
from wtforms.validators import InputRequired, Email, Length


class ToDoForm(FlaskForm):
    to_do = StringField(label="Task", validators=[InputRequired()])
    submit = SubmitField("Add")


class RegisterForm(FlaskForm):
    name = StringField(label="Name", validators=[InputRequired()])
    username = EmailField(label="Email", validators=[InputRequired(), Email()])
    password = PasswordField(label="Password", validators=[InputRequired(), Length(min=8)])
    submit = SubmitField("Sign Me Up!")


class LoginForm(FlaskForm):
    username = EmailField(label="Email", validators=[InputRequired(), Email()])
    password = PasswordField(label="Password", validators=[InputRequired()])
    submit = SubmitField("Let Me In!")
