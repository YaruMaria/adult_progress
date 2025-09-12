from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SubmitField
from wtforms.validators import DataRequired, Length

class TestForm(FlaskForm):
    title = StringField('Название теста', validators=[
        DataRequired(message="Название теста обязательно."),
        Length(min=1, max=100, message="Название должно быть от 1 до 100 символов.")
    ])
    description = TextAreaField('Описание теста', validators=[
        DataRequired(message="Описание теста обязательно."),
        Length(min=1, max=500, message="Описание должно быть от 1 до 500 символов.")
    ])
    submit = SubmitField('Создать тест')
