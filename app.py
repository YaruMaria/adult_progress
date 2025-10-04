from flask import Flask, render_template, request, redirect, url_for, session, flash, abort, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import os
import json
import random

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///progress.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Создание папки uploads, если она не существует
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)

# Модели
class Teacher(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

class Student(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    full_name = db.Column(db.String(120), nullable=False)
    start_date = db.Column(db.Date, nullable=False)
    initial_level = db.Column(db.String(50), nullable=False)
    goal = db.Column(db.String(100), nullable=False)
    stars = db.Column(db.Integer, default=0)
    teacher_id = db.Column(db.Integer, db.ForeignKey('teacher.id'), nullable=False)

    tests = db.relationship('Test', backref='student', lazy=True)

class Test(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('student.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    questions = db.relationship('Question', backref='test', lazy=True, cascade='all, delete-orphan')
    results = db.relationship('TestResult', backref='test', lazy=True, cascade='all, delete-orphan')

class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    test_id = db.Column(db.Integer, db.ForeignKey('test.id'), nullable=False)
    text = db.Column(db.Text, nullable=False)
    image_path = db.Column(db.String(300), nullable=True)  # Путь к изображению
    correct_answer = db.Column(db.Text, nullable=False)

class TestResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    test_id = db.Column(db.Integer, db.ForeignKey('test.id'), nullable=False)
    completed_at = db.Column(db.DateTime, default=datetime.utcnow)
    score = db.Column(db.Integer, nullable=False)
    total = db.Column(db.Integer, nullable=False)
    answers = db.Column(db.Text, nullable=False)  # JSON с ответами и правильными

# Вспомогательные функции
def is_logged_in():
    return 'teacher_id' in session

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'png', 'jpg', 'jpeg', 'gif'}

# Инициализация базы данных и создание учителя по умолчанию
with app.app_context():
    db.create_all()
    if not Teacher.query.filter_by(username='teacher').first():
        t = Teacher(username='teacher', password=generate_password_hash('pass'))
        db.session.add(t)
        db.session.commit()

# Маршруты
@app.route('/', methods=['GET', 'POST'])
def login():
    if is_logged_in():
        return redirect(url_for('teacher_dashboard'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        teacher = Teacher.query.filter_by(username=username).first()
        if teacher and check_password_hash(teacher.password, password):
            session['teacher_id'] = teacher.id
            session['username'] = teacher.username
            return redirect(url_for('teacher_dashboard'))
        else:
            flash('Неверный логин или пароль', 'error')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        if password != confirm_password:
            flash('Пароли не совпадают', 'error')
            return redirect(url_for('register'))
        if Teacher.query.filter_by(username=username).first():
            flash('Логин уже занят', 'error')
            return redirect(url_for('register'))
        t = Teacher(username=username, password=generate_password_hash(password))
        db.session.add(t)
        db.session.commit()
        flash('Регистрация успешна! Теперь войдите.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/dashboard')
def teacher_dashboard():
    if not is_logged_in():
        return redirect(url_for('login'))
    students = Student.query.filter_by(teacher_id=session['teacher_id']).all()
    total_stars = sum(s.stars for s in students)
    tests_count = Test.query.join(Student).filter(Student.teacher_id == session['teacher_id']).count()
    completed_tests = TestResult.query.join(Test).join(Student).filter(Student.teacher_id == session['teacher_id']).count()
    return render_template('teacher_dashboard.html',
                           students=students,
                           total_stars=total_stars,
                           test_count=tests_count,
                           completed_tests=completed_tests)

@app.route('/students')
def teacher_students():
    if not is_logged_in():
        return redirect(url_for('login'))
    students = Student.query.filter_by(teacher_id=session['teacher_id']).all()
    total_students = len(students)
    total_stars = sum(s.stars for s in students)
    active_students = len([s for s in students if s.tests])
    tests_completed = TestResult.query.join(Test).join(Student).filter(Student.teacher_id == session['teacher_id']).count()
    now_date = datetime.now().strftime('%Y-%m-%d')
    return render_template('teacher_students.html',
                           students=students,
                           total_students=total_students,
                           total_stars=total_stars,
                           active_students=active_students,
                           tests_completed=tests_completed,
                           now_date=now_date)

@app.route('/students/add', methods=['POST'])
def add_student():
    if not is_logged_in():
        return redirect(url_for('login'))
    username = request.form['username']
    full_name = request.form['full_name']
    start_date = request.form['start_date']
    initial_level = request.form['initial_level']
    goal = request.form['goal']

    if Student.query.filter_by(username=username).first():
        flash('Логин уже занят', 'error')
        return redirect(url_for('teacher_students'))

    student = Student(
        username=username,
        full_name=full_name,
        start_date=datetime.strptime(start_date, '%Y-%m-%d'),
        initial_level=initial_level,
        goal=goal,
        stars=0,
        teacher_id=session['teacher_id']
    )
    db.session.add(student)
    db.session.commit()
    flash('Ученик добавлен успешно', 'success')
    return redirect(url_for('teacher_students'))

@app.route('/student/<int:student_id>')
def student_profile(student_id):
    if not is_logged_in():
        return redirect(url_for('login'))
    student = Student.query.get_or_404(student_id)
    if student.teacher_id != session['teacher_id']:
        abort(403)
    return render_template('student_profile.html', student=student)

@app.route('/student/<int:student_id>/test/add', methods=['GET', 'POST'])
def add_test(student_id):
    if not is_logged_in():
        return redirect(url_for('login'))
    student = Student.query.get_or_404(student_id)
    if student.teacher_id != session['teacher_id']:
        abort(403)
    if request.method == 'POST':
        title = request.form['title']
        test = Test(student=student, title=title)
        db.session.add(test)
        db.session.commit()
        return redirect(url_for('add_questions', test_id=test.id))
    return render_template('create_test.html', student=student)

@app.route('/test/<int:test_id>/questions/add', methods=['GET', 'POST'])
def add_questions(test_id):
    if not is_logged_in():
        return redirect(url_for('login'))
    test = Test.query.get_or_404(test_id)
    if test.student.teacher_id != session['teacher_id']:
        abort(403)
    if request.method == 'POST':
        text = request.form['text']
        correct_answer = request.form['correct_answer']
        image_path = None
        if 'image' in request.files:
            file = request.files['image']
            if file and file.filename != '' and allowed_file(file.filename):
                # Создаем уникальное имя файла
                filename = secure_filename(file.filename)
                unique_filename = f"{datetime.now().strftime('%Y%m%d_%H%M%S_')}{filename}"
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
                file.save(filepath)
                image_path = unique_filename  # Сохраняем только имя файла
        question = Question(test=test, text=text, correct_answer=correct_answer, image_path=image_path)
        db.session.add(question)
        db.session.commit()
        flash('Вопрос добавлен', 'success')
        return redirect(url_for('add_questions', test_id=test_id))
    return render_template('add_question.html', test=test)

@app.route('/test/<int:test_id>/take', methods=['GET', 'POST'])
def take_test(test_id):
    test = Test.query.get_or_404(test_id)
    if test.student.teacher_id != session['teacher_id']:
        abort(403)
    questions = test.questions
    if request.method == 'POST':
        answers = {}
        correct_count = 0
        total = len(questions)
        for q in questions:
            ans = request.form.get(f'answer_{q.id}', '').strip()
            answers[str(q.id)] = {'user': ans, 'correct': q.correct_answer, 'is_correct': ans.lower() == q.correct_answer.lower()}
            if ans.lower() == q.correct_answer.lower():
                correct_count += 1
        result = TestResult(test=test, score=correct_count, total=total, answers=json.dumps(answers))
        db.session.add(result)
        test.student.stars += correct_count
        db.session.commit()
        return redirect(url_for('test_result', result_id=result.id))
    return render_template('take_test.html', test=test, questions=questions)

@app.route('/result/<int:result_id>')
def test_result(result_id):
    if not is_logged_in():
        return redirect(url_for('login'))
    result = TestResult.query.get_or_404(result_id)
    if result.test.student.teacher_id != session['teacher_id']:
        abort(403)
    answers = json.loads(result.answers)
    return render_template('test_result.html', result=result, answers=answers)

@app.route('/student/<int:student_id>/results')
def student_results(student_id):
    if not is_logged_in():
        return redirect(url_for('login'))
    student = Student.query.get_or_404(student_id)
    if student.teacher_id != session['teacher_id']:
        abort(403)
    results = TestResult.query.join(Test).filter(Test.student_id == student_id).order_by(TestResult.completed_at.desc()).all()
    return render_template('student_results.html', student=student, results=results)

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

if __name__ == '__main__':
    app.run(debug=True)

