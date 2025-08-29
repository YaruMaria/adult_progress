from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from dateutil.relativedelta import relativedelta
import sqlite3
import os
from functools import wraps
from flask_wtf.csrf import CSRFProtect
import json

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your-secret-key-here')
app.config['SESSION_PERMANENT'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
app.config['WTF_CSRF_ENABLED'] = True

# Инициализация CSRF защиты
csrf = CSRFProtect(app)

# Конфигурация базы данных
DB_PATH = os.path.join(os.path.abspath(os.path.dirname(__file__)), "school.db")

# Константы для системы мастерской
WORKSHOP_LEVELS = {
    1: {"name": "Начинающий кузнец", "tools": ["молоток", "наковальня"], "max_quality": 60},
    2: {"name": "Подмастерье", "tools": ["тиски", "зубило"], "max_quality": 75},
    3: {"name": "Мастер", "tools": ["горн", "пресс"], "max_quality": 90},
    4: {"name": "Великий мастер", "tools": ["станок", "микрометр"], "max_quality": 100}
}

RESOURCE_VALUES = {
    'understanding': {'coal': 2, 'iron': 1},
    'participation': {'coal': 1, 'iron': 2},
    'homework': {'coal': 3, 'steel': 1}
}

SHOP_ITEMS = [
    {"id": 1, "name": "Улучшенный молоток", "type": "tool", "price": 50, "effect": "+10% к качеству"},
    {"id": 2, "name": "Тисочный станок", "type": "tool", "price": 100, "effect": "+15% к скорости"},
    {"id": 3, "name": "Набор резцов", "type": "tool", "price": 80, "effect": "+5 к деталям"},
    {"id": 4, "name": "Кованый подсвечник", "type": "decoration", "price": 45, "effect": "украшение"},
    {"id": 5, "name": "Чертеж часов", "type": "blueprint", "price": 150, "effect": "новый проект"},
    {"id": 6, "name": "Обсидиановая накладка", "type": "material", "price": 200, "effect": "редкий материал"}
]

def get_db():
    """Устанавливает соединение с базой данных"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# Конфигурация базы данных
DB_PATH = os.path.join(os.path.abspath(os.path.dirname(__file__)), "school.db")

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
                    role TEXT NOT NULL CHECK(role IN ('teacher', 'parent', 'admin')),
                    is_teacher BOOLEAN DEFAULT 0
                );

                CREATE TABLE students (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    level TEXT,
                    start_date TEXT,
                    goal TEXT,
                    teacher_id INTEGER,
                    workshop_level INTEGER DEFAULT 1,
                    resources TEXT DEFAULT '{"coal": 0, "iron": 0, "steel": 0, "quality_gems": 0}',
                    current_project TEXT DEFAULT 'Простые инструменты',
                    FOREIGN KEY (teacher_id) REFERENCES users(id)
                );

                CREATE TABLE lessons (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    student_id INTEGER NOT NULL,
                    date TEXT NOT NULL,
                    topic TEXT NOT NULL,
                    understanding INTEGER DEFAULT 0,
                    participation INTEGER DEFAULT 0,
                    homework TEXT,
                    quality_score INTEGER DEFAULT 0,
                    resources_earned TEXT DEFAULT '{}',
                    FOREIGN KEY (student_id) REFERENCES students(id)
                );

                CREATE TABLE monthly_awards (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    student_id INTEGER NOT NULL,
                    year INTEGER NOT NULL,
                    month INTEGER NOT NULL,
                    award INTEGER,
                    project_completed TEXT,
                    FOREIGN KEY (student_id) REFERENCES students(id),
                    UNIQUE(student_id, year, month)
                );

                CREATE TABLE parents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    student_id INTEGER NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users(id),
                    FOREIGN KEY (student_id) REFERENCES students(id),
                    UNIQUE(user_id, student_id)
                );

                CREATE TABLE workshop_items (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    student_id INTEGER NOT NULL,
                    item_id INTEGER NOT NULL,
                    purchased_date TEXT NOT NULL,
                    is_equipped BOOLEAN DEFAULT 0,
                    FOREIGN KEY (student_id) REFERENCES students(id)
                );
            """)
            conn.commit()
            print("Таблицы успешно созданы")
        else:
            print("Таблицы уже существуют")
    except sqlite3.Error as e:
        print(f"Ошибка при инициализации базы данных: {e}")
        raise
    finally:
        conn.close()


def calculate_workshop_resources(understanding, participation, homework):
    """Рассчитывает ресурсы, полученные за урок"""
    resources = {'coal': 0, 'iron': 0, 'steel': 0, 'quality_gems': 0}

    # За понимание - уголь и железо
    resources['coal'] += understanding * RESOURCE_VALUES['understanding']['coal']
    resources['iron'] += understanding * RESOURCE_VALUES['understanding']['iron']

    # За участие - уголь и железо
    resources['coal'] += participation * RESOURCE_VALUES['participation']['coal']
    resources['iron'] += participation * RESOURCE_VALUES['participation']['iron']

    # За домашнюю работу - уголь и сталь
    homework_value = int(homework) if homework.isdigit() else 0
    resources['coal'] += homework_value * RESOURCE_VALUES['homework']['coal']
    if homework_value >= 3:  # Только за качественную работу
        resources['steel'] += homework_value * RESOURCE_VALUES['homework']['steel']

    # Качество детали (шанс получить самоцветы)
    quality_score = (understanding * 20 + participation * 15 + homework_value * 10) // 3
    if quality_score >= 90:
        resources['quality_gems'] = 1

    return resources, quality_score


def get_workshop_level_data(level):
    """Возвращает данные о уровне мастерской"""
    return WORKSHOP_LEVELS.get(level, WORKSHOP_LEVELS[1])

def create_first_teacher():
    """Создает учетную запись администратора по умолчанию"""
    try:
        conn = get_db()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM users WHERE is_teacher = 1")
        if not cursor.fetchone():
            hashed_password = generate_password_hash("admin123")
            cursor.execute(
                "INSERT INTO users (username, password, role, is_teacher) VALUES (?, ?, ?, ?)",
                ("admin", hashed_password, "admin", 1)
            )
            conn.commit()
            print("Создан учитель по умолчанию: admin/admin123")
    except sqlite3.Error as e:
        print(f"Ошибка при создании учителя: {e}")
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
        if not session.get('is_teacher'):
            flash('Эта функция доступна только учителям', 'error')
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated_function

# Маршруты аутентификации
@app.route('/')
def index():
    """Перенаправляет на вход, даже если пользователь был авторизован ранее"""
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
                    'SELECT id, username, password, is_teacher, role FROM users WHERE username = ?',
                    (username,)
                )
                user = cursor.fetchone()

            if user and check_password_hash(user['password'], password):
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['is_teacher'] = bool(user['is_teacher'])
                session['is_parent'] = user['role'] == 'parent'
                flash('Вы успешно вошли в систему', 'success')
                return redirect(url_for('home'))

            flash('Неверный логин или пароль', 'error')
        except Exception as e:
            flash('Ошибка при входе в систему', 'error')
            print(f"Ошибка входа: {e}")

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '').strip()
            confirm_password = request.form.get('confirm_password', '').strip()
            role = request.form.get('role', 'parent')

            # Валидация
            errors = []
            if len(username) < 3:
                errors.append('Логин должен содержать минимум 3 символа')
            if len(password) < 6:
                errors.append('Пароль должен содержать минимум 6 символов')
            if password != confirm_password:
                errors.append('Пароли не совпадают')
            if role not in ['teacher', 'parent']:
                errors.append('Необходимо выбрать роль')

            if errors:
                for error in errors:
                    flash(error, 'error')
                return render_template('register.html', username=username)

            hashed_password = generate_password_hash(password)
            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    'INSERT INTO users (username, password, role, is_teacher) VALUES (?, ?, ?, ?)',
                    (username, hashed_password, role, 1 if role == 'teacher' else 0)
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

@app.route('/find_student', methods=['GET', 'POST'])
@login_required
def find_student():
    if not session.get('is_parent'):
        return redirect(url_for('home'))

    search_name = request.form.get('student_name', '').strip()
    students = []

    try:
        if search_name:
            conn = get_db()
            cursor = conn.cursor()

            # Ищем по имени или фамилии (если введены оба слова)
            search_terms = search_name.split()
            query = """
                SELECT s.id, s.name, s.level, s.start_date, s.goal, 
                       u.username as teacher_name 
                FROM students s
                LEFT JOIN users u ON s.teacher_id = u.id
                WHERE {}
                ORDER BY s.name
            """.format(
                " AND ".join(["s.name LIKE ?" for _ in search_terms])
            )

            params = [f'%{term}%' for term in search_terms]
            cursor.execute(query, params)
            students = cursor.fetchall()

            # Логирование для отладки
            app.logger.debug(f"Search for '{search_name}' returned {len(students)} results")
            if students:
                app.logger.debug(f"Found students: {[s['name'] for s in students]}")

    except Exception as e:
        app.logger.error(f"Search error: {str(e)}")
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'error': str(e)}), 500

    # AJAX-запрос
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        if 'error' in locals():
            return jsonify({'error': 'Ошибка при поиске'}), 500
        html = render_template('_student_results.html',
                               students=students,
                               search_name=search_name)
        return jsonify({'html': html})

    return render_template('find_student.html',
                           students=students,
                           search_name=search_name)

@app.route('/link_student/<int:student_id>')
@login_required
def link_student(student_id):
    if not session.get('is_parent'):
        return redirect(url_for('home'))

    try:
        conn = get_db()
        cursor = conn.cursor()

        # Проверяем, что студент существует
        cursor.execute("SELECT id FROM students WHERE id = ?", (student_id,))
        if not cursor.fetchone():
            flash('Ученик не найден', 'error')
            return redirect(url_for('find_student'))

        # Связываем родителя с учеником
        cursor.execute(
            "INSERT OR IGNORE INTO parents (user_id, student_id) VALUES (?, ?)",
            (session['user_id'], student_id)
        )
        conn.commit()
        flash('Ученик успешно привязан к вашему аккаунту', 'success')

    except Exception as e:
        conn.rollback()
        flash('Произошла ошибка при привязке ученика', 'error')
        print(f"Ошибка привязки ученика: {e}")
    finally:
        conn.close()

    return redirect(url_for('parent_dashboard'))

@app.route('/parent_dashboard')
@login_required
def parent_dashboard():
    if not session.get('is_parent'):
        return redirect(url_for('home'))

    conn = get_db()
    cursor = conn.cursor()

    # Получаем всех привязанных учеников
    cursor.execute("""
        SELECT s.id, s.name, s.level 
        FROM students s
        JOIN parents p ON s.id = p.student_id
        WHERE p.user_id = ?
    """, (session['user_id'],))
    students = cursor.fetchall()

    conn.close()

    return render_template('parent_dashboard.html', students=students)

@app.route('/logout')
def logout():
    session.clear()
    flash('Вы успешно вышли из системы', 'success')
    return redirect(url_for('login'))

# Основные маршруты
@app.route("/home")
@login_required
def home():
    """Страница 'Мои ученики'"""
    if session.get('is_parent'):
        return redirect(url_for('parent_dashboard'))

    conn = sqlite3.connect("school.db")
    cursor = conn.cursor()

    if session.get('is_teacher'):
        cursor.execute("SELECT * FROM students WHERE teacher_id = ?", (session['user_id'],))
    else:
        cursor.execute("SELECT * FROM students LIMIT 0")

    students = cursor.fetchall()
    conn.close()
    return render_template("index.html", students=students)


@app.route("/student/<int:student_id>")
@login_required
def student(student_id):
    """Страница ученика с системой мастерской"""
    conn = get_db()
    cursor = conn.cursor()

    try:
        # Проверяем права доступа
        if session.get('is_teacher'):
            cursor.execute("""
                SELECT s.*, u.username as teacher_name 
                FROM students s
                LEFT JOIN users u ON s.teacher_id = u.id
                WHERE s.id = ? AND s.teacher_id = ?
            """, (student_id, session['user_id']))
        elif session.get('is_parent'):
            cursor.execute("""
                SELECT s.*, u.username as teacher_name 
                FROM students s
                LEFT JOIN users u ON s.teacher_id = u.id
                JOIN parents p ON s.id = p.student_id
                WHERE s.id = ? AND p.user_id = ?
            """, (student_id, session['user_id']))
        else:
            cursor.execute("SELECT * FROM students WHERE id = ? LIMIT 0", (student_id,))

        student = cursor.fetchone()

        if not student:
            flash("Ученик не найден или у вас нет прав доступа", "error")
            return redirect(url_for("home"))

        # Для учителей создаем недостающие уроки
        if session.get('is_teacher'):
            cursor.execute("SELECT COUNT(*) FROM lessons WHERE student_id = ?", (student_id,))
            lesson_count = cursor.fetchone()[0]

            if lesson_count < 8:
                for i in range(lesson_count + 1, 9):
                    cursor.execute(
                        "INSERT INTO lessons (student_id, date, topic) VALUES (?, ?, ?)",
                        (student_id, datetime.now().strftime("%Y-%m-%d"), f"Ковка детали {i}")
                    )
                conn.commit()

        # Получаем уроки с данными мастерской
        cursor.execute("""
            SELECT id, student_id, date, topic, 
                   COALESCE(understanding, 0) as understanding,
                   COALESCE(participation, 0) as participation,
                   COALESCE(NULLIF(homework, ''), '0') as homework,
                   quality_score, resources_earned
            FROM lessons 
            WHERE student_id = ? 
            ORDER BY id ASC
            LIMIT 8
        """, (student_id,))
        lessons = cursor.fetchall()

        # Получаем данные мастерской
        resources = json.loads(
            student['resources'] if student['resources'] else '{"coal": 0, "iron": 0, "steel": 0, "quality_gems": 0}')
        workshop_level = student['workshop_level'] or 1
        current_project = student['current_project'] or 'Простые инструменты'

        # Получаем купленные предметы (исправленный запрос)
        cursor.execute("""
            SELECT wi.* 
            FROM workshop_items wi
            WHERE wi.student_id = ?
        """, (student_id,))
        workshop_items = cursor.fetchall()

        # Создаем список купленных предметов с информацией из SHOP_ITEMS
        purchased_items = []
        for item in workshop_items:
            shop_item = next((si for si in SHOP_ITEMS if si['id'] == item['item_id']), None)
            if shop_item:
                purchased_items.append({
                    'id': item['id'],
                    'item_id': item['item_id'],
                    'name': shop_item['name'],
                    'type': shop_item['type'],
                    'effect': shop_item['effect'],
                    'purchased_date': item['purchased_date'],
                    'is_equipped': item['is_equipped']
                })

        # Проверяем, является ли текущий пользователь учителем этого ученика
        is_current_teacher = session.get('is_teacher') and student['teacher_id'] == session['user_id']

        # Получаем уровень мастерской
        workshop_data = get_workshop_level_data(workshop_level)

    except Exception as e:
        flash("Произошла ошибка при загрузке данных ученика", "error")
        print(f"Ошибка загрузки ученика: {e}")
        print(f"Тип ошибки: {type(e).__name__}")
        import traceback
        traceback.print_exc()
        return redirect(url_for("home"))
    finally:
        conn.close()

    return render_template("student.html",
                           student=student,
                           lessons=lessons,
                           resources=resources,
                           workshop_level=workshop_level,
                           workshop_data=workshop_data,
                           current_project=current_project,
                           workshop_items=purchased_items,  # Используем исправленный список
                           is_current_teacher=is_current_teacher,
                           current_date=datetime.now(),
                           relativedelta=relativedelta)


def migrate_db():
    """Обновляет структуру базы данных до актуальной версии"""
    print("Проверка миграций базы данных...")
    try:
        conn = get_db()
        cursor = conn.cursor()

        # Проверяем существование новых колонок
        cursor.execute("PRAGMA table_info(lessons)")
        columns = [col[1] for col in cursor.fetchall()]

        # Добавляем отсутствующие колонки
        if 'quality_score' not in columns:
            print("Добавляем колонку quality_score в таблицу lessons")
            cursor.execute("ALTER TABLE lessons ADD COLUMN quality_score INTEGER DEFAULT 0")

        if 'resources_earned' not in columns:
            print("Добавляем колонку resources_earned в таблицу lessons")
            cursor.execute("ALTER TABLE lessons ADD COLUMN resources_earned TEXT DEFAULT '{}'")

        # Проверяем таблицу students
        cursor.execute("PRAGMA table_info(students)")
        columns = [col[1] for col in cursor.fetchall()]

        if 'workshop_level' not in columns:
            print("Добавляем колонку workshop_level в таблицу students")
            cursor.execute("ALTER TABLE students ADD COLUMN workshop_level INTEGER DEFAULT 1")

        if 'resources' not in columns:
            print("Добавляем колонку resources в таблицу students")
            cursor.execute(
                "ALTER TABLE students ADD COLUMN resources TEXT DEFAULT '{\"coal\": 0, \"iron\": 0, \"steel\": 0, \"quality_gems\": 0}'")

        if 'current_project' not in columns:
            print("Добавляем колонку current_project в таблицу students")
            cursor.execute("ALTER TABLE students ADD COLUMN current_project TEXT DEFAULT 'Простые инструменты'")

        # Проверяем существование таблицы workshop_items
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='workshop_items'")
        if not cursor.fetchone():
            print("Создаем таблицу workshop_items")
            cursor.execute("""
                CREATE TABLE workshop_items (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    student_id INTEGER NOT NULL,
                    item_id INTEGER NOT NULL,
                    purchased_date TEXT NOT NULL,
                    is_equipped BOOLEAN DEFAULT 0,
                    FOREIGN KEY (student_id) REFERENCES students(id)
                )
            """)

        conn.commit()
        print("Миграция базы данных завершена")

    except sqlite3.Error as e:
        print(f"Ошибка при миграции базы данных: {e}")
        raise
    finally:
        conn.close()

@app.route("/set_coins/<int:lesson_id>/<string:coin_type>", methods=["POST"])
@login_required
def set_coins(lesson_id, coin_type):
    try:
        coins = int(request.form['coins'])
        student_id = request.form['student_id']

        conn = get_db()
        cursor = conn.cursor()

        # Проверяем права доступа
        cursor.execute("""
            SELECT 1 FROM lessons l
            JOIN students s ON l.student_id = s.id
            WHERE l.id = ? AND s.teacher_id = ?
        """, (lesson_id, session['user_id']))

        if not cursor.fetchone():
            return jsonify({'error': 'Доступ запрещён'}), 403

        # Обновляем данные и рассчитываем ресурсы
        if coin_type == 'homework':
            cursor.execute("""
                UPDATE lessons SET homework = ?
                WHERE id = ?
            """, (str(coins), lesson_id))
        else:
            cursor.execute(f"""
                UPDATE lessons SET {coin_type} = ?
                WHERE id = ?
            """, (coins, lesson_id))

        # Получаем текущие значения для расчета ресурсов
        cursor.execute("""
            SELECT understanding, participation, homework 
            FROM lessons WHERE id = ?
        """, (lesson_id,))
        lesson_data = cursor.fetchone()

        understanding = lesson_data['understanding'] or 0
        participation = lesson_data['participation'] or 0
        homework = lesson_data['homework'] or '0'

        # Рассчитываем ресурсы и качество
        resources, quality_score = calculate_workshop_resources(
            understanding, participation, homework
        )

        # Обновляем ресурсы в уроке
        cursor.execute("""
            UPDATE lessons 
            SET quality_score = ?, resources_earned = ?
            WHERE id = ?
        """, (quality_score, json.dumps(resources), lesson_id))

        # Обновляем общие ресурсы ученика
        cursor.execute("SELECT resources FROM students WHERE id = ?", (student_id,))
        student_resources = json.loads(cursor.fetchone()['resources'] or '{}')

        for resource, amount in resources.items():
            student_resources[resource] = student_resources.get(resource, 0) + amount

        cursor.execute("""
            UPDATE students SET resources = ? WHERE id = ?
        """, (json.dumps(student_resources), student_id))

        conn.commit()

        return jsonify({
            'success': True,
            'coins': coins,
            'resources': resources,
            'quality_score': quality_score,
            'total_resources': student_resources,
            'updated_at': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })

    except Exception as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()


@app.route("/workshop/shop")
@login_required
def workshop_shop():
    """Магазин предметов для мастерской"""
    student_id = request.args.get('student_id')

    if not student_id or not session.get('is_teacher'):
        return redirect(url_for('home'))

    conn = get_db()
    cursor = conn.cursor()

    # Проверяем права доступа
    cursor.execute("""
        SELECT 1 FROM students 
        WHERE id = ? AND teacher_id = ?
    """, (student_id, session['user_id']))

    if not cursor.fetchone():
        flash("Доступ запрещен", "error")
        return redirect(url_for('home'))

    # Получаем ресурсы ученика
    cursor.execute("SELECT resources FROM students WHERE id = ?", (student_id,))
    student = cursor.fetchone()
    resources = json.loads(student['resources'] if student['resources'] else '{}')

    conn.close()

    return render_template('workshop_shop.html',
                           shop_items=SHOP_ITEMS,
                           resources=resources,
                           student_id=student_id)


@app.route("/workshop/buy_item", methods=["POST"])
@login_required
@teacher_required
def buy_workshop_item():
    """Покупка предмета в магазине"""
    try:
        item_id = int(request.form['item_id'])
        student_id = int(request.form['student_id'])

        conn = get_db()
        cursor = conn.cursor()

        # Проверяем права доступа
        cursor.execute("""
            SELECT 1 FROM students 
            WHERE id = ? AND teacher_id = ?
        """, (student_id, session['user_id']))

        if not cursor.fetchone():
            return jsonify({'error': 'Доступ запрещен'}), 403

        # Получаем предмет и ресурсы ученика
        item = next((i for i in SHOP_ITEMS if i['id'] == item_id), None)
        if not item:
            return jsonify({'error': 'Предмет не найден'}), 404

        cursor.execute("SELECT resources FROM students WHERE id = ?", (student_id,))
        student = cursor.fetchone()
        resources = json.loads(student['resources'] if student['resources'] else '{}')

        # Проверяем достаточно ли ресурсов
        if resources.get('coal', 0) < item['price']:
            return jsonify({'error': 'Недостаточно угля'}), 400

        # Списание ресурсов
        resources['coal'] -= item['price']

        # Добавляем предмет
        cursor.execute("""
            INSERT INTO workshop_items (student_id, item_id, purchased_date)
            VALUES (?, ?, ?)
        """, (student_id, item_id, datetime.now().strftime("%Y-%m-%d")))

        # Обновляем ресурсы
        cursor.execute("""
            UPDATE students SET resources = ? WHERE id = ?
        """, (json.dumps(resources), student_id))

        conn.commit()

        return jsonify({
            'success': True,
            'item': item,
            'remaining_coal': resources['coal'],
            'message': f'Предмет "{item["name"]}" приобретен!'
        })

    except Exception as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()


@app.route("/workshop/upgrade", methods=["POST"])
@login_required
@teacher_required
def upgrade_workshop():
    """Улучшение уровня мастерской"""
    try:
        student_id = int(request.form['student_id'])

        conn = get_db()
        cursor = conn.cursor()

        # Проверяем права доступа
        cursor.execute("""
            SELECT workshop_level, resources FROM students 
            WHERE id = ? AND teacher_id = ?
        """, (student_id, session['user_id']))

        student = cursor.fetchone()
        if not student:
            return jsonify({'error': 'Доступ запрещен'}), 403

        current_level = student['workshop_level'] or 1
        resources = json.loads(student['resources'] if student['resources'] else '{}')

        # Стоимость улучшения
        upgrade_cost = current_level * 100  # 100, 200, 300 угля

        if resources.get('coal', 0) < upgrade_cost:
            return jsonify({'error': f'Недостаточно угля. Нужно: {upgrade_cost}'}), 400

        if current_level >= max(WORKSHOP_LEVELS.keys()):
            return jsonify({'error': 'Максимальный уровень достигнут'}), 400

        # Списание ресурсов и улучшение
        resources['coal'] -= upgrade_cost
        new_level = current_level + 1

        cursor.execute("""
            UPDATE students 
            SET workshop_level = ?, resources = ?
            WHERE id = ?
        """, (new_level, json.dumps(resources), student_id))

        conn.commit()

        return jsonify({
            'success': True,
            'new_level': new_level,
            'level_data': WORKSHOP_LEVELS[new_level],
            'remaining_coal': resources['coal'],
            'message': f'Мастерская улучшена до уровня {new_level}!'
        })

    except Exception as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()





@app.route("/update_homework/<int:lesson_id>", methods=["POST"])
@login_required
def update_homework(lesson_id):
    homework = request.form.get("homework", "")
    student_id = request.form.get("student_id")

    conn = sqlite3.connect("school.db")
    cursor = conn.cursor()
    try:
        cursor.execute(
            "UPDATE lessons SET homework = ? WHERE id = ?",
            (homework, lesson_id))
        conn.commit()
        return jsonify({'status': 'success'})
    except Exception as e:
        conn.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 500
    finally:
        conn.close()

@app.route("/student/<int:student_id>/awards")
@login_required
def student_awards(student_id):
    current_date = datetime.now()
    selected_month = request.args.get('month', current_date.month, type=int)
    selected_year = request.args.get('year', current_date.year, type=int)

    conn = sqlite3.connect("school.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM students WHERE id = ?", (student_id,))
    student = cursor.fetchone()

    cursor.execute("SELECT year, month, award FROM monthly_awards WHERE student_id = ?", (student_id,))
    awards = {(year, month): award for year, month, award in cursor.fetchall()}
    conn.close()

    months = []
    for i in range(-3, 3):
        date = datetime(selected_year, selected_month, 1) + relativedelta(months=i)
        months.append({
            'year': date.year,
            'month': date.month,
            'name': date.strftime('%B'),
            'is_current': (date.year == current_date.year and date.month == current_date.month),
            'award': awards.get((date.year, date.month))
        })

    return render_template("awards.html",
                         student=student,
                         months=months,
                         current_date=current_date,
                         selected_month=selected_month,
                         selected_year=selected_year)

@app.route("/update_award", methods=["POST"])
@login_required
def update_award():
    student_id = request.form.get("student_id")
    year = int(request.form.get("year"))
    month = int(request.form.get("month"))
    award = int(request.form.get("award"))

    conn = sqlite3.connect("school.db")
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT OR REPLACE INTO monthly_awards 
            (student_id, year, month, award) 
            VALUES (?, ?, ?, ?)
        """, (student_id, year, month, award))
        conn.commit()
        return jsonify({'status': 'success'})
    except Exception as e:
        conn.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 500
    finally:
        conn.close()
@app.route("/add_student", methods=["POST"])
@login_required
@teacher_required
def add_student():
    name = request.form.get("name", "").strip()
    level = request.form.get("level", "").strip()
    start_date = request.form.get("start_date", "").strip()
    goal = request.form.get("goal", "").strip()

    errors = []
    if not name:
        errors.append("Имя ученика обязательно")
    elif len(name) > 50:
        errors.append("Имя слишком длинное (макс. 50 символов)")

    if errors:
        for error in errors:
            flash(error, "error")
        return redirect(url_for("home"))

    conn = sqlite3.connect("school.db")
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO students (name, level, start_date, goal, teacher_id) VALUES (?, ?, ?, ?, ?)",
            (name, level if level else None,
             start_date if start_date else None,
             goal if goal else None,
             session['user_id'])
        )
        conn.commit()
        flash("Ученик добавлен!", "success")
        return redirect(url_for("success"))  # Перенаправление на страницу успеха
    except sqlite3.IntegrityError:
        flash("Ученик с таким именем уже существует", "error")
    except Exception as e:
        flash(f"Ошибка при добавлении ученика: {str(e)}", "error")
    finally:
        conn.close()

    return redirect(url_for("home"))


@app.route("/success")
@login_required
def success():
    """Страница успешного добавления ученика"""
    return render_template("success.html")


with app.app_context():
    init_db()
    migrate_db()  # Добавьте эту строку
    create_first_teacher()
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)