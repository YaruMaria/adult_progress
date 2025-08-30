from datetime import datetime
import sqlite3
import os
import json
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf.csrf import CSRFProtect, generate_csrf

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your-secret-key-here')
app.config['SESSION_PERMANENT'] = False

# Добавьте CSRF защиту
csrf = CSRFProtect(app)

@app.context_processor
def utility_processor():
    return dict(datetime=datetime)
# Конфигурация базы данных
DB_PATH = os.path.join(os.path.abspath(os.path.dirname(__file__)), "education.db")

# Система достижений
# Система достижений (добавьте в начало файла)
ACHIEVEMENTS = {
    1: {"name": "Новичок", "stars_required": 1, "message": "Поздравляем! Вы получили первую звезду и теперь Новичок!"},
    5: {"name": "Ученик", "stars_required": 5, "message": "Отлично! Вы достигли уровня Ученика!"},
    15: {"name": "Знаток", "stars_required": 15, "message": "Поздравляем! Теперь вы Знаток!"},
    30: {"name": "Эксперт", "stars_required": 30, "message": "Великолепно! Вы достигли уровня Эксперта!"},
    50: {"name": "Мастер", "stars_required": 50, "message": "Потрясающе! Вы настоящий Мастер обучения!"},
    100: {"name": "Гуру", "stars_required": 100, "message": "Невероятно! Вы достигли высшего уровня - Гуру!"}
}


def get_db():
    """Устанавливает соединение с базой данных"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Инициализирует базу данных и создает таблицы"""
    print(f"Инициализация базы данных по пути: {DB_PATH}")
    try:
        conn = get_db()
        cursor = conn.cursor()

        # Проверяем существование таблиц
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
        if not cursor.fetchone():
            # Создаем таблицы, если они не существуют
            cursor.executescript("""
                CREATE TABLE users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    role TEXT NOT NULL CHECK(role IN ('student', 'teacher', 'admin')),
                    stars INTEGER DEFAULT 0,
                    achievements TEXT DEFAULT '[]',
                    current_rank TEXT DEFAULT 'Нет статуса'
                );

                CREATE TABLE tests (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    description TEXT,
                    creator_id INTEGER NOT NULL,
                    questions TEXT NOT NULL,
                    created_date TEXT NOT NULL,
                    updated_date TEXT,
                    FOREIGN KEY (creator_id) REFERENCES users(id)
                );

                CREATE TABLE test_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    test_id INTEGER NOT NULL,
                    student_id INTEGER NOT NULL,
                    score INTEGER NOT NULL,
                    total_questions INTEGER NOT NULL,
                    percentage INTEGER NOT NULL,
                    stars_earned INTEGER NOT NULL,
                    answers TEXT NOT NULL,
                    completed_date TEXT NOT NULL,
                    FOREIGN KEY (test_id) REFERENCES tests(id),
                    FOREIGN KEY (student_id) REFERENCES users(id)
                );

                CREATE TABLE student_achievements (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    student_id INTEGER NOT NULL,
                    achievement_id INTEGER NOT NULL,
                    achieved_date TEXT NOT NULL,
                    FOREIGN KEY (student_id) REFERENCES users(id)
                );
            """)
            conn.commit()
            print("Таблицы успешно созданы")
        else:
            print("Таблицы уже существуют")

        # Обновляем структуру базы данных
        update_db_schema()

    except sqlite3.Error as e:
        print(f"Ошибка при инициализации базы данных: {e}")
        raise
    finally:
        conn.close()


@app.context_processor
def inject_csrf_token():
    return dict(csrf_token=generate_csrf)

def create_first_admin():
    """Создает учетную запись администратора по умолчанию"""
    try:
        conn = get_db()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM users WHERE role = 'admin'")
        if not cursor.fetchone():
            hashed_password = generate_password_hash("admin123")
            cursor.execute(
                "INSERT INTO users (username, password, role, current_rank) VALUES (?, ?, ?, ?)",
                ("admin", hashed_password, "admin", "Администратор")
            )
            conn.commit()
            print("Создан администратор по умолчанию: admin/admin123")
    except sqlite3.Error as e:
        print(f"Ошибка при создании администратора: {e}")
        raise
    finally:
        conn.close()


# Декораторы для проверки прав
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Пожалуйста, войдите для доступа к этой странице', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)

    return decorated_function


def teacher_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('role') != 'teacher' and session.get('role') != 'admin':
            flash('Эта функция доступна только учителям', 'error')
            return redirect(url_for('home'))
        return f(*args, **kwargs)

    return decorated_function


def student_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('role') != 'student':
            flash('Эта функция доступна только ученикам', 'error')
            return redirect(url_for('home'))
        return f(*args, **kwargs)

    return decorated_function


# Маршруты аутентификации
@app.route('/')
def index():
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        try:
            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    'SELECT id, username, password, role, stars, current_rank FROM users WHERE username = ?',
                    (username,)
                )
                user = cursor.fetchone()

            if user and check_password_hash(user['password'], password):
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['role'] = user['role']
                session['stars'] = user['stars']
                session['current_rank'] = user['current_rank']

                flash('Вы успешно вошли в систему', 'success')

                if user['role'] == 'student':
                    return redirect(url_for('student_dashboard'))
                else:
                    return redirect(url_for('teacher_dashboard'))

            flash('Неверный логин или пароль', 'error')
        except Exception as e:
            flash('Ошибка при входе в систему', 'error')
            print(f"Ошибка входа: {e}")

    return render_template('login.html')


def update_db_schema():
    """Обновляет структуру базы данных, добавляя новые столбцы"""
    try:
        conn = get_db()
        cursor = conn.cursor()

        # Проверяем существование столбца student_id в таблице tests
        cursor.execute("PRAGMA table_info(tests)")
        columns = [column[1] for column in cursor.fetchall()]

        if 'student_id' not in columns:
            cursor.execute("ALTER TABLE tests ADD COLUMN student_id INTEGER")
            print("Добавлен столбец student_id в tests")
            conn.commit()

        conn.close()

    except sqlite3.Error as e:
        print(f"Ошибка при обновлении структуры базы данных: {e}")
        raise


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '').strip()
            confirm_password = request.form.get('confirm_password', '').strip()
            role = request.form.get('role', 'student')

            # Валидация
            errors = []
            if len(username) < 3:
                errors.append('Логин должен содержать минимум 3 символа')
            if len(password) < 6:
                errors.append('Пароль должен содержать минимум 6 символов')
            if password != confirm_password:
                errors.append('Пароли не совпадают')
            if role not in ['student', 'teacher']:
                errors.append('Необходимо выбрать роль')

            if errors:
                for error in errors:
                    flash(error, 'error')
                return render_template('register.html', username=username)

            hashed_password = generate_password_hash(password)
            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    'INSERT INTO users (username, password, role, current_rank) VALUES (?, ?, ?, ?)',
                    (username, hashed_password, role, 'Новичок' if role == 'student' else 'Учитель')
                )
                conn.commit()

            flash('Регистрация успешна! Теперь войдите', 'success')
            return redirect(url_for('login'))

        except sqlite3.IntegrityError:
            flash('Пользователь с таким именем уже существует', 'error')
        except Exception as e:
            flash('Произошла ошибка при регистрации', 'error')
            print(f"Ошибка регистрации: {e}")

    return render_template('register.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('Вы успешно вышли из системы', 'success')
    return redirect(url_for('login'))


# Основные маршруты
@app.route("/home")
@login_required
def home():
    if session.get('role') == 'student':
        return redirect(url_for('student_dashboard'))
    else:
        return redirect(url_for('teacher_dashboard'))




@app.route("/teacher/dashboard")
@login_required
@teacher_required
def teacher_dashboard():
    """Главная страница учителя с выбором ученика"""
    conn = get_db()
    cursor = conn.cursor()

    try:
        # Получаем учеников с преобразованием в словари
        cursor.execute("""
            SELECT id, username, full_name, stars, current_rank, 
                   initial_level, start_date, goal 
            FROM users 
            WHERE role = 'student' AND teacher_id = ?
            ORDER BY created_date DESC
        """, (session['user_id'],))

        students = [dict(row) for row in cursor.fetchall()]

        # Получаем статистику для dashboard
        cursor.execute("SELECT COUNT(*) as total FROM users WHERE role = 'student' AND teacher_id = ?",
                       (session['user_id'],))
        total_students = cursor.fetchone()['total']

        cursor.execute("SELECT SUM(stars) as total_stars FROM users WHERE role = 'student' AND teacher_id = ?",
                       (session['user_id'],))
        total_stars = cursor.fetchone()['total_stars'] or 0

        cursor.execute("SELECT COUNT(*) as test_count FROM tests WHERE creator_id = ?",
                       (session['user_id'],))
        test_count = cursor.fetchone()['test_count']

        cursor.execute("SELECT COUNT(*) as completed FROM test_results")
        completed_tests = cursor.fetchone()['completed']

    except sqlite3.Error as e:
        print(f"Ошибка при получении данных: {e}")
        students = []
        total_students = 0
        total_stars = 0
        test_count = 0
        completed_tests = 0

    finally:
        conn.close()

    return render_template("teacher_dashboard.html",
                           students=students,
                           total_students=total_students,
                           total_stars=total_stars,
                           test_count=test_count,
                           completed_tests=completed_tests)


@app.route("/tests")
@login_required
def tests_list():
    """Список всех тестов"""
    conn = get_db()
    cursor = conn.cursor()

    if session.get('role') == 'student':
        cursor.execute("""
            SELECT t.id, t.title, t.description, t.created_date, u.username as creator_name,
                   CASE WHEN tr.id IS NOT NULL THEN 1 ELSE 0 END as completed
            FROM tests t
            JOIN users u ON t.creator_id = u.id
            LEFT JOIN test_results tr ON t.id = tr.test_id AND tr.student_id = ?
            ORDER BY t.created_date DESC
        """, (session['user_id'],))
    else:
        cursor.execute("""
            SELECT t.id, t.title, t.description, t.created_date, u.username as creator_name,
                   COUNT(tr.id) as completions
            FROM tests t
            JOIN users u ON t.creator_id = u.id
            LEFT JOIN test_results tr ON t.id = tr.test_id
            GROUP BY t.id
            ORDER BY t.created_date DESC
        """)

    tests = cursor.fetchall()
    conn.close()

    return render_template("tests_list.html", tests=tests)


@app.route("/test/create", methods=['GET', 'POST'])
@login_required
@teacher_required
def create_test():
    """Создание нового теста"""
    if request.method == 'POST':
        try:
            title = request.form.get('title', '').strip()
            description = request.form.get('description', '').strip()

            # Получаем вопросы из формы
            questions = []
            question_count = 0

            for i in range(1, 11):  # Максимум 10 вопросов
                question_text = request.form.get(f'question_{i}', '').strip()
                answer = request.form.get(f'answer_{i}', '').strip()

                if question_text and answer:
                    questions.append({
                        'question': question_text,
                        'answer': answer
                    })
                    question_count += 1

            if question_count == 0:
                flash('Добавьте хотя бы один вопрос', 'error')
                return render_template('create_test.html')

            # Сохраняем тест в базу данных
            conn = get_db()
            cursor = conn.cursor()

            cursor.execute(
                "INSERT INTO tests (title, description, creator_id, questions, created_date) VALUES (?, ?, ?, ?, ?)",
                (title, description, session['user_id'], json.dumps(questions),
                 datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            )

            conn.commit()
            conn.close()

            flash('Тест успешно создан!', 'success')
            return redirect(url_for('tests_list'))

        except Exception as e:
            flash('Произошла ошибка при создании теста', 'error')
            print(f"Ошибка создания теста: {e}")

    return render_template('create_test.html')


@app.route("/test/<int:test_id>/edit", methods=['GET', 'POST'])
@login_required
@teacher_required
def edit_test(test_id):
    """Редактирование теста"""
    conn = get_db()
    cursor = conn.cursor()

    # Проверяем права доступа
    cursor.execute("SELECT * FROM tests WHERE id = ?", (test_id,))
    test = cursor.fetchone()

    if not test:
        flash('Тест не найден', 'error')
        return redirect(url_for('tests_list'))

    if request.method == 'POST':
        try:
            title = request.form.get('title', '').strip()
            description = request.form.get('description', '').strip()

            # Получаем вопросы из формы
            questions = []
            question_count = 0

            for i in range(1, 11):  # Максимум 10 вопросов
                question_text = request.form.get(f'question_{i}', '').strip()
                answer = request.form.get(f'answer_{i}', '').strip()

                if question_text and answer:
                    questions.append({
                        'question': question_text,
                        'answer': answer
                    })
                    question_count += 1

            if question_count == 0:
                flash('Добавьте хотя бы один вопрос', 'error')
                return render_template('edit_test.html', test=test)

            # Обновляем тест в базе данных
            cursor.execute(
                "UPDATE tests SET title = ?, description = ?, questions = ?, updated_date = ? WHERE id = ?",
                (title, description, json.dumps(questions), datetime.now().strftime("%Y-%m-%d %H:%M:%S"), test_id)
            )

            conn.commit()
            conn.close()

            flash('Тест успешно обновлен!', 'success')
            return redirect(url_for('tests_list'))

        except Exception as e:
            flash('Произошла ошибка при обновлении теста', 'error')
            print(f"Ошибка обновления теста: {e}")

    # Загружаем вопросы для редактирования
    questions = json.loads(test['questions']) if test['questions'] else []

    conn.close()
    return render_template('edit_test.html', test=test, questions=questions)



@app.route("/results/<int:result_id>")
@login_required
def test_results(result_id):
    """Просмотр результатов теста"""
    conn = get_db()
    cursor = conn.cursor()

    # Получаем результат
    cursor.execute("""
        SELECT tr.*, t.title as test_title, u.username as student_name
        FROM test_results tr
        JOIN tests t ON tr.test_id = t.id
        JOIN users u ON tr.student_id = u.id
        WHERE tr.id = ?
    """, (result_id,))

    result = cursor.fetchone()

    if not result:
        flash('Результат не найден', 'error')
        return redirect(url_for('home'))

    # Проверяем права доступа
    if session.get('role') == 'student' and result['student_id'] != session['user_id']:
        flash('У вас нет прав для просмотра этого результата', 'error')
        return redirect(url_for('home'))

    answers = json.loads(result['answers']) if result['answers'] else []

    conn.close()
    return render_template('test_results.html', result=result, answers=answers)


def check_achievements(student_id, cursor):
    """Проверяет и присваивает достижения на основе количества звезд"""
    # Получаем текущее количество звезд
    cursor.execute("SELECT stars FROM users WHERE id = ?", (student_id,))
    stars = cursor.fetchone()['stars']

    # Получаем уже полученные достижения
    cursor.execute("SELECT achievement_id FROM student_achievements WHERE student_id = ?", (student_id,))
    achieved_ids = [row['achievement_id'] for row in cursor.fetchall()]

    # Проверяем, какие достижения нужно присвоить
    messages = []
    for achievement_id, achievement in ACHIEVEMENTS.items():
        if achievement_id not in achieved_ids and stars >= achievement['stars_required']:
            # Присваиваем достижение
            cursor.execute(
                "INSERT INTO student_achievements (student_id, achievement_id, achieved_date) VALUES (?, ?, ?)",
                (student_id, achievement_id, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            )

            # Обновляем текущий ранг
            cursor.execute(
                "UPDATE users SET current_rank = ? WHERE id = ?",
                (achievement['name'], student_id)
            )

            # Сообщение о достижении
            messages.append(achievement['message'])

    return messages

@app.route("/teacher/student/<int:student_id>/test/<int:test_id>/take")
@login_required
@teacher_required
def take_test(test_id, student_id):
    """Страница прохождения теста"""
    conn = get_db()
    cursor = conn.cursor()

    # Получаем тест
    cursor.execute("SELECT * FROM tests WHERE id = ? AND student_id = ?", (test_id, student_id))
    test = cursor.fetchone()

    if not test:
        flash('Тест не найден', 'error')
        return redirect(url_for('student_dashboard', student_id=student_id))

    questions = json.loads(test['questions']) if test['questions'] else []
    question_index = int(request.args.get('question_index', 0))

    # Получаем сохраненные ответы из сессии
    session_key = f'test_{test_id}_answers'
    user_answers = session.get(session_key, []) or ['' for _ in questions]

    conn.close()

    return render_template("test_take.html",
                         test=test,
                         questions=questions,
                         current_question=question_index,
                         total_questions=len(questions),
                         user_answers=user_answers,
                         student_id=student_id)


@app.route("/teacher/student/<int:student_id>/test/<int:test_id>/answer/<int:question_index>", methods=['POST'])
@login_required
@teacher_required
def process_test_answer(test_id, student_id, question_index):
    """Обработка ответа на вопрос теста"""
    conn = get_db()
    cursor = conn.cursor()

    # Получаем тест
    cursor.execute("SELECT * FROM tests WHERE id = ? AND student_id = ?", (test_id, student_id))
    test = cursor.fetchone()
    questions = json.loads(test['questions']) if test['questions'] else []

    # Сохраняем ответ в сессии
    session_key = f'test_{test_id}_answers'
    user_answers = session.get(session_key, []) or ['' for _ in questions]
    user_answers[question_index] = request.form.get('answer', '').strip()
    session[session_key] = user_answers

    # Если это последний вопрос, завершаем тест
    if request.form.get('finish') and question_index == len(questions) - 1:
        return finish_test(test_id, student_id, questions, user_answers, cursor, conn)

    # Переходим к следующему вопросу
    next_question = min(question_index + 1, len(questions) - 1)
    conn.close()

    return redirect(url_for('take_test', test_id=test_id, student_id=student_id, question_index=next_question))


def finish_test(test_id, student_id, questions, user_answers, cursor, conn):
    """Завершение теста и подсчет результатов"""
    # Получаем данные теста
    cursor.execute("SELECT * FROM tests WHERE id = ?", (test_id,))
    test = cursor.fetchone()

    if not test:
        flash('Тест не найден', 'error')
        return redirect(url_for('student_dashboard', student_id=student_id))

    # Проверяем ответы
    correct_answers = 0
    results = []

    for i, question in enumerate(questions):
        is_correct = user_answers[i].lower() == question['answer'].lower()
        if is_correct:
            correct_answers += 1

        results.append({
            'question': question['question'],
            'user_answer': user_answers[i],
            'correct_answer': question['answer'],
            'is_correct': is_correct
        })

    # Вычисляем результаты
    total_questions = len(questions)
    percentage = round((correct_answers / total_questions) * 100) if total_questions > 0 else 0

    # Начисляем звезды в зависимости от процента правильных ответов
    if percentage >= 90:
        stars_earned = 3
    elif percentage >= 70:
        stars_earned = 2
    elif percentage >= 50:
        stars_earned = 1
    else:
        stars_earned = 0

    # Сохраняем результат
    cursor.execute(
        """INSERT INTO test_results 
        (test_id, student_id, score, total_questions, percentage, stars_earned, answers, completed_date) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (test_id, student_id, correct_answers, total_questions, percentage,
         stars_earned, json.dumps(results), datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    )

    # Обновляем общее количество звезд ученика
    if stars_earned > 0:
        cursor.execute(
            "UPDATE users SET stars = stars + ? WHERE id = ?",
            (stars_earned, student_id)
        )

        # Проверяем достижения
        achievement_messages = check_achievements(student_id, cursor)

    conn.commit()
    result_id = cursor.lastrowid

    # Очищаем ответы из сессии
    session_key = f'test_{test_id}_answers'
    if session_key in session:
        del session[session_key]

    conn.close()

    return render_template("test_complete.html",
                           test=test,
                           result={
                               'percentage': percentage,
                               'stars_earned': stars_earned,
                               'score': correct_answers,
                               'total_questions': total_questions
                           },
                           answers=results,
                           achievement_messages=achievement_messages or [],
                           student_id=student_id)


@app.route("/achievements")
@login_required
def achievements():
    """Страница с достижениями"""
    conn = get_db()
    cursor = conn.cursor()

    if session.get('role') == 'student':
        # Для ученика - показываем его достижения
        cursor.execute("""
            SELECT sa.achievement_id, sa.achieved_date
            FROM student_achievements sa
            WHERE sa.student_id = ?
            ORDER BY sa.achievement_id
        """, (session['user_id'],))

        student_achievements = cursor.fetchall()

        # Получаем текущий прогресс
        cursor.execute("SELECT stars, current_rank FROM users WHERE id = ?", (session['user_id'],))
        user = cursor.fetchone()

        conn.close()
        return render_template('student_achievements.html',
                               student_achievements=student_achievements,
                               user=user,
                               all_achievements=ACHIEVEMENTS)

    else:
        # Для учителя - показываем достижения всех учеников
        cursor.execute("""
            SELECT u.username, u.stars, u.current_rank, 
                   COUNT(sa.achievement_id) as achievements_count,
                   MAX(sa.achieved_date) as last_achievement
            FROM users u
            LEFT JOIN student_achievements sa ON u.id = sa.student_id
            WHERE u.role = 'student'
            GROUP BY u.id
            ORDER BY u.stars DESC
        """)

        students = cursor.fetchall()
        conn.close()

        return render_template('teacher_achievements.html', students=students)


@app.route("/profile")
@login_required
def profile():
    """Страница профиля пользователя"""
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT username, role, stars, current_rank FROM users WHERE id = ?", (session['user_id'],))
    user = cursor.fetchone()

    if session.get('role') == 'student':
        # Для ученика - получаем статистику
        cursor.execute("""
            SELECT COUNT(*) as tests_taken, 
                   SUM(stars_earned) as total_stars_earned,
                   AVG(percentage) as average_score
            FROM test_results 
            WHERE student_id = ?
        """, (session['user_id'],))

        stats = cursor.fetchone()

        conn.close()
        return render_template('student_profile.html', user=user, stats=stats)

    else:
        # Для учителя - получаем статистику созданных тестов
        cursor.execute("""
            SELECT COUNT(*) as tests_created,
                   COUNT(DISTINCT tr.student_id) as students_using,
                   SUM(tr.stars_earned) as total_stars_given
            FROM tests t
            LEFT JOIN test_results tr ON t.id = tr.test_id
            WHERE t.creator_id = ?
        """, (session['user_id'],))

        stats = cursor.fetchone()

        conn.close()
        return render_template('teacher_profile.html', user=user, stats=stats)


# Запуск приложения
with app.app_context():
    init_db()
    create_first_admin()


@app.route("/teacher/students")
@login_required
@teacher_required
def teacher_students():
    """Страница управления учениками"""
    conn = get_db()
    cursor = conn.cursor()

    try:
        # Проверяем существование столбцов
        cursor.execute("PRAGMA table_info(users)")
        columns = [column[1] for column in cursor.fetchall()]

        # Формируем запрос в зависимости от наличия столбцов
        if 'teacher_id' in columns:
            cursor.execute("""
                SELECT u.id, u.username, u.full_name, u.stars, u.current_rank, 
                       u.start_date, u.goal, u.initial_level,
                       COUNT(tr.id) as tests_completed,
                       MAX(tr.completed_date) as last_activity
                FROM users u
                LEFT JOIN test_results tr ON u.id = tr.student_id
                WHERE u.role = 'student' AND u.teacher_id = ?
                GROUP BY u.id
                ORDER BY u.username
            """, (session['user_id'],))
        else:
            cursor.execute("""
                SELECT u.id, u.username, u.username as full_name, u.stars, u.current_rank,
                       'Не указана' as start_date, 'Не указана' as goal, 'Не указан' as initial_level,
                       COUNT(tr.id) as tests_completed,
                       MAX(tr.completed_date) as last_activity
                FROM users u
                LEFT JOIN test_results tr ON u.id = tr.student_id
                WHERE u.role = 'student'
                GROUP BY u.id
                ORDER BY u.username
            """)

        students = cursor.fetchall()

        # Статистика
        if 'teacher_id' in columns:
            cursor.execute("SELECT COUNT(*) as total FROM users WHERE role = 'student' AND teacher_id = ?",
                           (session['user_id'],))
        else:
            cursor.execute("SELECT COUNT(*) as total FROM users WHERE role = 'student'")
        total_students = cursor.fetchone()['total']

        cursor.execute("SELECT SUM(stars) as total FROM users WHERE role = 'student'")
        total_stars = cursor.fetchone()['total'] or 0

        cursor.execute("SELECT COUNT(DISTINCT student_id) as active FROM test_results")
        active_students = cursor.fetchone()['active']

        cursor.execute("SELECT COUNT(*) as total FROM test_results")
        tests_completed = cursor.fetchone()['total']

    except sqlite3.Error as e:
        print(f"Ошибка при получении данных: {e}")
        students = []
        total_students = 0
        total_stars = 0
        active_students = 0
        tests_completed = 0

    finally:
        conn.close()

    # Передаем текущую дату для значения по умолчанию
    now_date = datetime.now().strftime('%Y-%m-%d')

    return render_template("teacher_students.html",
                           students=students,
                           total_students=total_students,
                           total_stars=total_stars,
                           active_students=active_students,
                           tests_completed=tests_completed,
                           now_date=now_date)


@app.route("/teacher/students/add", methods=['POST'])
@login_required
@teacher_required
def add_student():
    """Добавление нового ученика с автоматической генерацией пароля"""
    try:
        username = request.form.get('username', '').strip()
        full_name = request.form.get('full_name', '').strip()
        start_date = request.form.get('start_date', '').strip()
        goal = request.form.get('goal', '').strip()
        initial_level = request.form.get('initial_level', '').strip()

        # Валидация
        errors = []
        if len(username) < 3:
            errors.append('Логин должен содержать минимум 3 символа')
        if not full_name:
            errors.append('Укажите имя ученика')
        if not start_date:
            errors.append('Укажите дату начала занятий')
        if not goal:
            errors.append('Укажите цель обучения')
        if not initial_level:
            errors.append('Укажите начальный уровень')

        if errors:
            for error in errors:
                flash(error, 'error')
            return redirect(url_for('teacher_students'))

        # Проверяем, существует ли уже пользователь с таким username
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        existing_user = cursor.fetchone()

        if existing_user:
            flash('Пользователь с таким логином уже существует', 'error')
            conn.close()
            return redirect(url_for('teacher_students'))

        # Генерируем автоматический пароль (6 цифр)
        import random
        password = str(random.randint(100000, 999999))
        hashed_password = generate_password_hash(password)

        current_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        cursor.execute(
            '''INSERT INTO users 
            (username, password, role, current_rank, stars, 
             full_name, start_date, goal, initial_level, teacher_id, created_date) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
            (username, hashed_password, 'student', 'Новичок', 0,
             full_name, start_date, goal, initial_level, session['user_id'], current_date)
        )

        conn.commit()
        conn.close()

        flash(f'Ученик {full_name} успешно добавлен! Логин: {username}, Пароль: {password}', 'success')

    except sqlite3.Error as e:
        flash('Произошла ошибка при добавлении ученика', 'error')
        print(f"Ошибка добавления ученика: {e}")
    except Exception as e:
        flash('Произошла непредвиденная ошибка', 'error')
        print(f"Ошибка добавления ученика: {e}")

    return redirect(url_for('teacher_students'))


@app.route("/teacher/student/<int:student_id>/dashboard")
@login_required
@teacher_required
def student_dashboard(student_id):
    """Профиль ученика с тестами"""
    conn = get_db()
    cursor = conn.cursor()

    # Получаем данные ученика
    cursor.execute("SELECT * FROM users WHERE id = ? AND role = 'student'", (student_id,))
    student = cursor.fetchone()

    if not student:
        flash('Ученик не найден', 'error')
        return redirect(url_for('teacher_students'))

    # Получаем тесты для этого ученика
    cursor.execute("SELECT * FROM tests WHERE student_id = ? ORDER BY created_date DESC", (student_id,))
    tests = []
    for test in cursor.fetchall():
        test_dict = dict(test)
        test_dict['questions'] = json.loads(test['questions']) if test['questions'] else []
        tests.append(test_dict)

    # Получаем результаты тестов
    cursor.execute("""
        SELECT tr.*, t.title as test_title 
        FROM test_results tr 
        JOIN tests t ON tr.test_id = t.id 
        WHERE tr.student_id = ? 
        ORDER BY tr.completed_date DESC
    """, (student_id,))
    test_results = cursor.fetchall()

    conn.close()

    return render_template("student_dashboard.html",
                           student=student,
                           tests=tests,
                           test_results=test_results)


@app.route("/teacher/student/<int:student_id>/test/create", methods=['POST'])
@login_required
@teacher_required
def create_test_for_student(student_id):
    """Создание теста для конкретного ученика"""
    try:
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()

        # Получаем вопросы из формы
        questions = []
        question_count = 0

        for i in range(1, 11):  # Проверяем до 10 вопросов
            question_text = request.form.get(f'question_{i}', '').strip()
            answer = request.form.get(f'answer_{i}', '').strip()

            if question_text and answer:  # Добавляем только если оба поля заполнены
                questions.append({
                    'question': question_text,
                    'answer': answer
                })
                question_count += 1

        if question_count == 0:
            flash('Добавьте хотя бы один вопрос', 'error')
            return redirect(url_for('student_dashboard', student_id=student_id))

        # Сохраняем тест в базу данных
        conn = get_db()
        cursor = conn.cursor()

        cursor.execute(
            "INSERT INTO tests (title, description, creator_id, student_id, questions, created_date) VALUES (?, ?, ?, ?, ?, ?)",
            (title, description, session['user_id'], student_id, json.dumps(questions),
             datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        )

        conn.commit()
        conn.close()

        flash('Тест успешно создан!', 'success')

    except Exception as e:
        flash('Произошла ошибка при создании теста', 'error')
        print(f"Ошибка создания теста: {e}")

    return redirect(url_for('student_dashboard', student_id=student_id))

@app.route("/teacher/students/delete/<int:student_id>", methods=['POST'])
@login_required
@teacher_required
def delete_student(student_id):
    """Удаление ученика"""
    try:
        with get_db() as conn:
            cursor = conn.cursor()

            # Проверяем, что пользователь является учеником
            cursor.execute("SELECT username FROM users WHERE id = ? AND role = 'student'", (student_id,))
            student = cursor.fetchone()

            if not student:
                return jsonify({'success': False, 'message': 'Ученик не найден'})

            # Удаляем связанные данные
            cursor.execute("DELETE FROM test_results WHERE student_id = ?", (student_id,))
            cursor.execute("DELETE FROM student_achievements WHERE student_id = ?", (student_id,))
            cursor.execute("DELETE FROM users WHERE id = ?", (student_id,))

            conn.commit()

        return jsonify({'success': True, 'message': f'Ученик {student["username"]} удалён'})

    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})


@app.route("/teacher/student/<int:student_id>")
@login_required
@teacher_required
def student_details(student_id):
    """Детальная страница ученика"""
    conn = get_db()
    cursor = conn.cursor()

    # Получаем данные ученика
    cursor.execute("SELECT * FROM users WHERE id = ? AND role = 'student'", (student_id,))
    student = cursor.fetchone()

    if not student:
        flash('Ученик не найден', 'error')
        return redirect(url_for('teacher_students'))

    # Получаем результаты тестов
    cursor.execute("""
        SELECT tr.*, t.title as test_title
        FROM test_results tr
        JOIN tests t ON tr.test_id = t.id
        WHERE tr.student_id = ?
        ORDER BY tr.completed_date DESC
    """, (student_id,))
    test_results = cursor.fetchall()

    # Получаем достижения ученика
    cursor.execute("SELECT achievement_id FROM student_achievements WHERE student_id = ?", (student_id,))
    student_achievements = [row['achievement_id'] for row in cursor.fetchall()]

    conn.close()

    return render_template("student_dashboard.html",
                           student=student,
                           test_results=test_results,
                           student_achievements=student_achievements,
                           achievements=ACHIEVEMENTS)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port, debug=True)