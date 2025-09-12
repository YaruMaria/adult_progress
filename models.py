from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()  # Предполагаю, что это ваш db

class Test(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    teacher_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Связь с преподавателем
    # Добавьте другие поля, если нужно (например, вопросы)
    questions = db.relationship('Question', backref='test', lazy=True)  # Если есть модель Question

    def __repr__(self):
        return f'<Test {self.title}>'
