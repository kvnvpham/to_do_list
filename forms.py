from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import InputRequired


class ToDoForm (FlaskForm):
    todo = StringField(label="Input Your Tasks", validators=[InputRequired()])
    submit = SubmitField("Add")
