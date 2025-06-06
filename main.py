from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, make_response
import os
import logging
import time
import re
import hashlib
import base64
import secrets
import json
import traceback
import atexit
from datetime import datetime

# Настройка логирования
logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "dev_secret_key")

# Имитация базы данных пользователей (в реальном приложении использовалась бы БД)
users_db = {
    # username: {salt: "...", password_hash: "...", role: "...", failed_attempts: 0, lockout_until: None, 
    #            first_name: "...", last_name: "...", middle_name: "..."}
}

# Имитация базы данных тестов
tests_db = {
    # test_id: {
    #   title: "...", description: "...", category: "...", 
    #   created_by: "...", created_at: timestamp,
    #   time_limit: N, passing_score: N, 
    #   questions: [
    #     {id: "...", text: "...", type: "single/multiple/text", points: N, 
    #      options: [
    #        {text: "...", is_correct: True/False}, 
    #        ...
    #      ],
    #      correct_answer: "..." (для текстовых вопросов)
    #     },
    #     ...
    #   ], 
    #   assigned_to: {
    #     groups: [...], 
    #     students: [...]
    #   },
    #   status: "draft/published"
    # }
}

# Имитация базы данных групп
groups_db = {
    # group_id: {name: "...", students: [...]}
}

# Имитация базы данных результатов тестов
test_results_db = {
    # result_id: {
    #   user_id: "...", 
    #   test_id: "...", 
    #   score: N, 
    #   max_score: N,
    #   grade: N, 
    #   completion_date: timestamp,
    #   time_spent: N,
    #   correct_answers: N,
    #   incorrect_answers: N,
    #   total_questions: N,
    #   detailed_results: [
    #     {question_id: "...", question_text: "...", student_answer: "...", 
    #      correct_answer: "...", is_correct: True/False, points_earned: N, max_points: N},
    #     ...
    #   ]
    # }
}

# Функции для сохранения и загрузки данных
def save_data():
    """Сохранение всех данных в JSON файл"""
    data = {
        'users_db': users_db,
        'tests_db': tests_db,
        'groups_db': groups_db,
        'test_results_db': test_results_db
    }
    try:
        with open('app_data.json', 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2, default=str)
        print("Данные успешно сохранены в app_data.json")
    except Exception as e:
        print(f"Ошибка при сохранении данных: {e}")

def load_data():
    """Загрузка данных из JSON файла"""
    global users_db, tests_db, groups_db, test_results_db
    try:
        if os.path.exists('app_data.json'):
            with open('app_data.json', 'r', encoding='utf-8') as f:
                data = json.load(f)
                users_db.update(data.get('users_db', {}))
                tests_db.update(data.get('tests_db', {}))
                groups_db.update(data.get('groups_db', {}))
                test_results_db.update(data.get('test_results_db', {}))
            print("Данные успешно загружены из app_data.json")
        else:
            print("Файл app_data.json не найден, используются начальные данные")
    except Exception as e:
        print(f"Ошибка при загрузке данных: {e}")

# Регистрируем функцию автосохранения при завершении программы
atexit.register(save_data)

# Шаблонные фильтры
@app.template_filter('time')
def _jinja2_filter_time(timestamp):
    return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')

@app.template_filter('strftime')
def _jinja2_filter_strftime(format_str):
    return datetime.now().strftime(format_str)

# Константы для безопасности
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION = 30 * 60  # 30 минут в секундах
AUTH_DELAY = 2  # задержка при неверных данных в секундах

# Функция для генерации соли
def generate_salt():
    return base64.b64encode(secrets.token_bytes(16)).decode('utf-8')

# Функция хеширования пароля с солью
def hash_password(password, salt):
    # Объединяем пароль и соль
    password_bytes = password.encode('utf-8')
    salt_bytes = base64.b64decode(salt)
    
    # Создаем хеш SHA-256
    hash_input = password_bytes + salt_bytes
    hash_bytes = hashlib.sha256(hash_input).digest()
    
    return base64.b64encode(hash_bytes).decode('utf-8')

# Функция проверки пароля
def verify_password(password, salt, password_hash):
    computed_hash = hash_password(password, salt)
    return computed_hash == password_hash

# Функция валидации учетных данных
def validate_credentials(username, password, check_username=True):
    # Проверка логина если требуется
    if check_username:
        if not username:
            return False, "Логин не может быть пустым"
        
        if len(username) < 3:
            return False, "Логин должен содержать минимум 3 символа"
    
    # Проверка пароля
    if not password:
        return False, "Пароль не может быть пустым"
    
    if len(password) < 8:
        return False, "Пароль должен содержать минимум 8 символов"
    
    # Проверка наличия букв и цифр в пароле
    has_letter = bool(re.search('[a-zA-Z]', password))
    has_digit = bool(re.search('[0-9]', password))
    
    if not (has_letter and has_digit):
        return False, "Пароль должен содержать как минимум одну букву и одну цифру"
    
    return True, ""

# Создаем тестовых пользователей при запуске
def create_test_users():
    # Загружаем существующие данные перед созданием тестовых пользователей
    load_data()
    
    test_users = [
        # Основные пользователи
        {"username": "admin", "password": "Password123", "role": "admin", "first_name": "Администратор", "last_name": "Системный", "middle_name": ""},
        {"username": "student", "password": "Student123", "role": "student", "first_name": "Иван", "last_name": "Студентов", "middle_name": "Петрович"},
        {"username": "teacher", "password": "Teacher123", "role": "teacher", "first_name": "Елена", "last_name": "Преподавателева", "middle_name": "Сергеевна"},
        
        # Студенты группы B-201
        {"username": "student_b1", "password": "Student123", "role": "student", "first_name": "Алексей", "last_name": "Смирнов", "middle_name": "Иванович"},
        {"username": "student_b2", "password": "Student123", "role": "student", "first_name": "Мария", "last_name": "Иванова", "middle_name": "Петровна"},
        {"username": "student_b3", "password": "Student123", "role": "student", "first_name": "Дмитрий", "last_name": "Козлов", "middle_name": "Андреевич"},
        {"username": "student_b4", "password": "Student123", "role": "student", "first_name": "Анна", "last_name": "Соколова", "middle_name": "Александровна"},
        {"username": "student_b5", "password": "Student123", "role": "student", "first_name": "Павел", "last_name": "Морозов", "middle_name": "Сергеевич"},
        
        # Студенты группы C-301
        {"username": "student_c1", "password": "Student123", "role": "student", "first_name": "Екатерина", "last_name": "Волкова", "middle_name": "Дмитриевна"},
        {"username": "student_c2", "password": "Student123", "role": "student", "first_name": "Николай", "last_name": "Петров", "middle_name": "Владимирович"},
        {"username": "student_c3", "password": "Student123", "role": "student", "first_name": "Ольга", "last_name": "Васильева", "middle_name": "Викторовна"},
        {"username": "student_c4", "password": "Student123", "role": "student", "first_name": "Сергей", "last_name": "Попов", "middle_name": "Алексеевич"},
        {"username": "student_c5", "password": "Student123", "role": "student", "first_name": "Юлия", "last_name": "Андреева", "middle_name": "Михайловна"},
        {"username": "student_c6", "password": "Student123", "role": "student", "first_name": "Максим", "last_name": "Лебедев", "middle_name": "Артемович"},
        
        # Студенты группы D-401
        {"username": "student_d1", "password": "Student123", "role": "student", "first_name": "Владислав", "last_name": "Новиков", "middle_name": "Алексеевич"},
        {"username": "student_d2", "password": "Student123", "role": "student", "first_name": "Татьяна", "last_name": "Макарова", "middle_name": "Игоревна"},
        {"username": "student_d3", "password": "Student123", "role": "student", "first_name": "Александр", "last_name": "Козлов", "middle_name": "Сергеевич"},
        {"username": "student_d4", "password": "Student123", "role": "student", "first_name": "Наталья", "last_name": "Соловьева", "middle_name": "Андреевна"},
        {"username": "student_d5", "password": "Student123", "role": "student", "first_name": "Андрей", "last_name": "Семенов", "middle_name": "Павлович"},
        {"username": "student_d6", "password": "Student123", "role": "student", "first_name": "Елизавета", "last_name": "Киреева", "middle_name": "Викторовна"}
    ]
    
    for user in test_users:
        username = user["username"]
        password = user["password"]
        role = user["role"]
        
        if username not in users_db:
            salt = generate_salt()
            password_hash = hash_password(password, salt)
            
            # Используем предоставленные имя, фамилию и отчество, если есть
            first_name = user.get("first_name", role.capitalize())
            last_name = user.get("last_name", "User")
            middle_name = user.get("middle_name", "")
            
            users_db[username] = {
                "salt": salt,
                "password_hash": password_hash,
                "password": password,  # Сохраняем пароль в открытом виде для отображения
                "role": role,
                "failed_attempts": 0,
                "lockout_until": None,
                "first_name": first_name,
                "last_name": last_name,
                "middle_name": middle_name,
                "name": f"{first_name} {last_name}",
                "email": f"{username}@example.com",
                "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "last_login": None
            }
            
            logging.info(f"Тестовый пользователь создан: {username} / {password} (роль: {role})")

# Создаем тестовые группы
def create_test_groups():
    if not groups_db:
        # Основная тестовая группа
        groups_db["group1"] = {
            "name": "Группа A-101",
            "students": ["student"],
            "description": "Группа студентов первого курса"
        }
        logging.info("Тестовая группа создана: Группа A-101")
        
        # Дополнительные группы по запросу пользователя
        groups_db["group2"] = {
            "name": "Группа B-201",
            "students": ["student_b1", "student_b2", "student_b3", "student_b4", "student_b5"],
            "description": "Группа студентов второго курса"
        }
        logging.info("Тестовая группа создана: Группа B-201")
        
        groups_db["group3"] = {
            "name": "Группа C-301",
            "students": ["student_c1", "student_c2", "student_c3", "student_c4", "student_c5", "student_c6"],
            "description": "Группа студентов третьего курса"
        }
        logging.info("Тестовая группа создана: Группа C-301")
        
        groups_db["group4"] = {
            "name": "Группа D-401",
            "students": ["student_d1", "student_d2", "student_d3", "student_d4", "student_d5", "student_d6"],
            "description": "Группа студентов четвертого курса"
        }
        logging.info("Тестовая группа создана: Группа D-401")

# Создаем тестовые тесты
def create_test_quiz():
    if not tests_db:
        # Первый тест - присвоен только группе A-101
        tests_db["test1"] = {
            "title": "Основы программирования",
            "description": "Тест на знание основ программирования",
            "category": "Программирование",
            "time_limit": 30,
            "visibility": "published",
            "created_by": "teacher",
            "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "questions": [
                {
                    "question": "Что такое переменная?",
                    "options": [
                        "Контейнер для хранения данных",
                        "Математическая формула",
                        "Тип данных",
                        "Функция в программировании"
                    ],
                    "correct_answer": 0
                },
                {
                    "question": "Какой язык программирования мы изучаем?",
                    "options": [
                        "Java",
                        "Python",
                        "C++",
                        "JavaScript"
                    ],
                    "correct_answer": 1
                }
            ],
            "assigned_to": {"groups": ["group1"], "students": []},
            "results": {}
        }
        
        # Второй тест - присвоен группам B-201 и C-301
        tests_db["test2"] = {
            "title": "Базы данных SQL",
            "description": "Тест на знание основ SQL и реляционных баз данных",
            "category": "Базы данных",
            "time_limit": 45,
            "visibility": "published",
            "created_by": "teacher",
            "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "questions": [
                {
                    "question": "Что такое SQL?",
                    "options": [
                        "Язык структурированных запросов",
                        "Система управления базами данных",
                        "Фреймворк для веб-разработки",
                        "Протокол передачи данных"
                    ],
                    "correct_answer": 0
                },
                {
                    "question": "Какая команда используется для выборки данных из таблицы?",
                    "options": [
                        "INSERT",
                        "UPDATE",
                        "SELECT",
                        "DELETE"
                    ],
                    "correct_answer": 2
                },
                {
                    "question": "Что такое первичный ключ?",
                    "options": [
                        "Поле, которое однозначно идентифицирует запись в таблице",
                        "Пароль для доступа к базе данных",
                        "Первая колонка в таблице",
                        "Ссылка на другую таблицу"
                    ],
                    "correct_answer": 0
                }
            ],
            "assigned_to": {"groups": ["group2", "group3"], "students": []},
            "results": {}
        }
        
        # Третий тест - назначен всем группам
        tests_db["test3"] = {
            "title": "Основы безопасности",
            "description": "Тест на знание основ информационной безопасности",
            "category": "Безопасность",
            "time_limit": 40,
            "visibility": "published",
            "created_by": "teacher",
            "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "questions": [
                {
                    "question": "Что такое хеширование паролей?",
                    "options": [
                        "Способ шифрования паролей для защиты от взлома",
                        "Метод сжатия данных",
                        "Процесс разделения пароля на части",
                        "Техника для ускорения доступа к паролям"
                    ],
                    "correct_answer": 0
                },
                {
                    "question": "Какая из перечисленных практик является наиболее безопасной?",
                    "options": [
                        "Хранение паролей в открытом виде",
                        "Хранение хеша пароля с солью",
                        "Шифрование пароля симметричным ключом",
                        "Сохранение пароля в cookie браузера"
                    ],
                    "correct_answer": 1
                }
            ],
            "assigned_to": {"groups": ["group1", "group2", "group3", "group4"], "students": []},
            "results": {}
        }
        logging.info("Тестовый тест создан: Основы программирования")

# Инициализация тестовых данных
create_test_users()
create_test_groups()
create_test_quiz()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Валидация входных данных
        is_valid, error_msg = validate_credentials(username, password)
        if not is_valid:
            flash(error_msg, 'danger')
            return render_template('login.html')
        
        # Проверка существования пользователя
        if username not in users_db:
            # Задержка для защиты от перебора
            time.sleep(AUTH_DELAY)
            flash("Неверный логин или пароль", 'danger')
            return render_template('login.html')
        
        user = users_db[username]
        
        # Проверка блокировки
        if user["lockout_until"] and time.time() < user["lockout_until"]:
            lockout_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(user["lockout_until"]))
            flash(f"Аккаунт заблокирован до {lockout_time}", 'danger')
            return render_template('login.html')
        
        # Проверка пароля
        if not verify_password(password, user["salt"], user["password_hash"]):
            # Увеличение счетчика неудачных попыток
            user["failed_attempts"] += 1
            
            # Блокировка при превышении лимита попыток
            if user["failed_attempts"] >= MAX_FAILED_ATTEMPTS:
                user["lockout_until"] = time.time() + LOCKOUT_DURATION
                lockout_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(user["lockout_until"]))
                
                # Задержка для защиты от перебора
                time.sleep(AUTH_DELAY)
                
                flash(f"Аккаунт заблокирован до {lockout_time} из-за превышения количества неудачных попыток входа", 'danger')
                return render_template('login.html')
            
            # Задержка для защиты от перебора
            time.sleep(AUTH_DELAY)
            
            flash("Неверный логин или пароль", 'danger')
            return render_template('login.html')
        
        # Сброс счетчика при успешном входе
        user["failed_attempts"] = 0
        user["lockout_until"] = None
        
        # Установка сессии
        session['logged_in'] = True
        session['username'] = username
        session['role'] = user["role"]
        
        # Перенаправление на страницу успешного входа
        return redirect(url_for('dashboard'))
    
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'logged_in' not in session or not session['logged_in']:
        flash('Пожалуйста, авторизуйтесь для доступа к этой странице', 'warning')
        return redirect(url_for('login'))
    
    role = session['role']
    username = session['username']
    
    # Обновляем время последнего входа
    if username in users_db:
        users_db[username]['last_login'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Перенаправляем на соответствующую ролевую панель
    if role == 'admin':
        return redirect(url_for('admin_dashboard'))
    elif role == 'student':
        return redirect(url_for('student_dashboard'))
    elif role == 'teacher':
        return redirect(url_for('teacher_dashboard'))
    else:
        # Для неизвестных ролей показываем общую панель
        return render_template('dashboard.html', 
                              username=username, 
                              role=role)

@app.route('/logout')
def logout():
    session.clear()
    flash('Вы успешно вышли из системы', 'success')
    return redirect(url_for('login'))

@app.route('/teacher/new_test_form')  # URL-адрес страницы
def new_test_form():
    return render_template('teacher/new_test_form.html')  # Путь к файлу в templates/

@app.route('/teacher/new_test')  # URL-адрес страницы
def new_test_form():
    return render_template('teacher/new_test.html')  # Путь к файлу в templates/

@app.route('/teacher/new_create_test')  # URL-адрес страницы
def new_test_form():
    return render_template('teacher/new_create_test.html')  # Путь к файлу в templates/

@app.route('/teacher/create_test')  # URL-адрес страницы
def new_test_form():
    return render_template('teacher/create_test.html')  # Путь к файлу в templates/
    
    
# Создание тестовых пользователей
@app.route('/create_test_users')
def create_test_users_route():
    create_test_users()
    create_test_groups()
    create_test_quiz()
    flash('Тестовые пользователи созданы: admin/Password123, student/Student123, teacher/Teacher123', 'success')
    return redirect(url_for('login'))

# АДМИНИСТРАТИВНАЯ ПАНЕЛЬ
@app.route('/admin/dashboard')
def admin_dashboard():
    if 'logged_in' not in session or not session['logged_in'] or session['role'] != 'admin':
        flash('У вас нет доступа к этой странице', 'danger')
        return redirect(url_for('login'))
    
    # Получаем информацию для админа
    users_count = len(users_db)
    tests_count = len(tests_db)
    groups_count = len(groups_db)
    
    return render_template('admin/dashboard.html', 
                          username=session['username'],
                          role=session['role'],
                          users_count=users_count,
                          tests_count=tests_count,
                          groups_count=groups_count)

@app.route('/admin/users')
def admin_users():
    if 'logged_in' not in session or not session['logged_in'] or session['role'] != 'admin':
        flash('У вас нет доступа к этой странице', 'danger')
        return redirect(url_for('login'))
    
    role_filter = request.args.get('role', '')
    group_filter = request.args.get('group', '')
    search_query = request.args.get('query', '')
    
    filtered_users = {}
    
    for username, user_data in users_db.items():
        # Фильтрация по роли, если указана
        if role_filter and user_data['role'] != role_filter:
            continue
            
        # Фильтрация по группе, если указана (только для студентов)
        if group_filter and user_data['role'] == 'student':
            # Проверяем принадлежность студента к группе
            user_in_group = False
            for group_id, group_data in groups_db.items():
                if group_id == group_filter and username in group_data['students']:
                    user_in_group = True
                    break
            
            if not user_in_group:
                continue
                
        # Фильтрация по поисковому запросу
        if search_query:
            search_terms = search_query.lower().split()
            user_data_text = f"{username} {user_data.get('name', '')} {user_data.get('email', '')}".lower()
            
            if not any(term in user_data_text for term in search_terms):
                continue
        
        # Если прошли все фильтры, добавляем пользователя в результат
        filtered_users[username] = user_data
    
    return render_template('admin/users.html', 
                          username=session['username'],
                          role=session['role'],
                          users=filtered_users,
                          groups=groups_db,
                          current_role_filter=role_filter,
                          current_group_filter=group_filter,
                          current_search_query=search_query)

@app.route('/admin/groups')
def admin_groups():
    if 'logged_in' not in session or not session['logged_in'] or session['role'] != 'admin':
        flash('У вас нет доступа к этой странице', 'danger')
        return redirect(url_for('login'))
    
    return render_template('admin/groups.html', 
                          username=session['username'],
                          role=session['role'],
                          groups=groups_db,
                          users=users_db,
                          tests=tests_db)

@app.route('/admin/groups/update/<group_id>', methods=['POST'])
def admin_update_group(group_id):
    if 'logged_in' not in session or not session['logged_in'] or session['role'] != 'admin':
        flash('У вас нет доступа к этой странице', 'danger')
        return redirect(url_for('login'))
    
    if group_id not in groups_db:
        flash('Группа не найдена', 'danger')
        return redirect(url_for('admin_groups'))
    
    group_name = request.form.get('group_name')
    group_description = request.form.get('group_description', '')
    
    if not group_name:
        flash('Название группы не может быть пустым', 'danger')
        return redirect(url_for('admin_groups'))
    
    # Проверяем, существует ли другая группа с таким же названием
    for gid, group in groups_db.items():
        if gid != group_id and group['name'].lower() == group_name.lower():
            flash(f'Группа с названием "{group_name}" уже существует', 'danger')
            return redirect(url_for('admin_groups'))
    
    # Обновляем информацию о группе
    groups_db[group_id]['name'] = group_name
    groups_db[group_id]['description'] = group_description
    
    flash(f'Информация о группе "{group_name}" успешно обновлена', 'success')
    return redirect(url_for('admin_groups'))

@app.route('/admin/tests')
def admin_tests():
    if 'logged_in' not in session or not session['logged_in'] or session['role'] != 'admin':
        flash('У вас нет доступа к этой странице', 'danger')
        return redirect(url_for('login'))
    
    return render_template('admin/tests.html', 
                          username=session['username'],
                          role=session['role'],
                          tests=tests_db,
                          groups=groups_db,
                          users=users_db)

@app.route('/admin/tests/edit/<test_id>', methods=['GET', 'POST'])
def admin_edit_test(test_id):
    if 'logged_in' not in session or not session['logged_in'] or session['role'] != 'admin':
        flash('У вас нет доступа к этой странице', 'danger')
        return redirect(url_for('login'))
    
    # Проверка существования теста
    if test_id not in tests_db:
        flash('Тест не найден', 'danger')
        return redirect(url_for('admin_tests'))
    
    # Если GET-запрос, отображаем форму редактирования
    if request.method == 'GET':
        test_data = tests_db[test_id].copy()  # Создаем копию, чтобы не менять оригинал
        
        # Для корректного отображения вопросов
        if 'questions' in test_data:
            # Для дебага: печатаем структуру вопросов
            print(f"Admin Edit - Структура вопросов в тесте: {test_data['questions'][:2]}")
            
            # Преобразуем вопросы в JSON для передачи в шаблон
            questions_json = json.dumps(test_data.get('questions', []))
            print(f"Admin Edit - JSON вопросов для шаблона: {questions_json[:100]}...")
        else:
            questions_json = "[]"
            print("Admin Edit - Вопросы отсутствуют в тесте!")
        
        return render_template('admin/edit_test.html', 
                              username=session['username'],
                              role=session['role'],
                              test=test_data,
                              test_id=test_id,
                              questions_json=questions_json,
                              is_admin=True)
    
    # Если POST-запрос, перенаправляем на общий обработчик для администратора
    return redirect(url_for('admin_tests_save'))

@app.route('/admin/tests/save', methods=['POST'])
def admin_tests_save():
    """Функция для сохранения теста администратором с поддержкой улучшенной функциональности"""
    if 'logged_in' not in session or not session['logged_in'] or session['role'] != 'admin':
        flash('У вас нет доступа к этой странице', 'danger')
        return redirect(url_for('login'))
    
    print("=" * 50)
    print("Сохранение теста администратором")
    
    # Получаем данные формы
    test_id = request.form.get('test_id')
    title = request.form.get('title', '')
    description = request.form.get('description', '')
    duration = request.form.get('duration', 0, type=int)
    passing_score = request.form.get('passing_score', 0, type=int)
    category = request.form.get('category', '')
    visibility = request.form.get('visibility', 'draft')
    
    # Получаем данные о вопросах из JSON
    questions_data = request.form.get('questions_data', '[]')
    try:
        questions = json.loads(questions_data)
        print(f"Получено {len(questions)} вопросов")
    except json.JSONDecodeError as e:
        print(f"Ошибка при разборе JSON: {e}")
        questions = []
    
    # Валидация основных данных
    if not title:
        flash('Название теста обязательно', 'danger')
        return redirect(url_for('admin_tests'))
    
    # Обновляем или создаем тест
    if test_id and test_id in tests_db:
        # Обновляем существующий тест
        tests_db[test_id]['title'] = title
        tests_db[test_id]['description'] = description
        tests_db[test_id]['category'] = category
        tests_db[test_id]['duration'] = duration
        tests_db[test_id]['passing_score'] = passing_score
        tests_db[test_id]['visibility'] = visibility
        tests_db[test_id]['questions'] = questions
        tests_db[test_id]['questions_count'] = len(questions)
        tests_db[test_id]['updated_at'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        tests_db[test_id]['updated_by'] = session['username']
        
        flash(f'Тест "{title}" успешно обновлен', 'success')
    else:
        # Создаем новый тест
        new_test_id = f"test_{int(time.time())}"
        tests_db[new_test_id] = {
            "id": new_test_id,
            "title": title,
            "description": description,
            "category": category,
            "duration": duration,
            "passing_score": passing_score,
            "visibility": visibility,
            "questions": questions,
            "questions_count": len(questions),
            "created_by": session['username'],
            "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "assigned_to": {"groups": [], "students": []}
        }
        
        flash(f'Тест "{title}" успешно создан', 'success')
    
    return redirect(url_for('admin_tests'))

@app.route('/admin/tests/assign/<test_id>', methods=['POST'])
def admin_assign_test(test_id):
    if 'logged_in' not in session or not session['logged_in'] or session['role'] != 'admin':
        flash('У вас нет доступа к этой странице', 'danger')
        return redirect(url_for('login'))
    
    if test_id not in tests_db:
        flash('Тест не найден', 'danger')
        return redirect(url_for('admin_tests'))
    
    # Получаем список групп, которым нужно назначить тест
    group_ids = request.form.getlist('groups')
    
    # Обновляем список групп, которым назначен тест
    # Если assigned_to всё ещё в старом формате (список), преобразуем его в новый формат
    if isinstance(tests_db[test_id]['assigned_to'], list):
        tests_db[test_id]['assigned_to'] = {"groups": tests_db[test_id]['assigned_to'], "students": []}
    else:
        tests_db[test_id]['assigned_to']["groups"] = group_ids
    
    flash(f'Тест "{tests_db[test_id]["title"]}" успешно назначен выбранным группам', 'success')
    return redirect(url_for('admin_tests'))

@app.route('/admin/backup')
def admin_backup():
    if 'logged_in' not in session or not session['logged_in'] or session['role'] != 'admin':
        flash('У вас нет доступа к этой странице', 'danger')
        return redirect(url_for('login'))
    
    # Для демонстрации просто формируем JSON данных
    backup_data = {
        "users": users_db,
        "tests": tests_db,
        "groups": groups_db,
        "results": test_results_db,
        "backup_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    
    return render_template('admin/backup.html', 
                          username=session['username'],
                          role=session['role'],
                          backup_data=json.dumps(backup_data, indent=2))

@app.route('/admin/backup/download')
def admin_backup_download():
    if 'logged_in' not in session or not session['logged_in'] or session['role'] != 'admin':
        flash('У вас нет доступа к этой функции', 'danger')
        return redirect(url_for('login'))
    
    # Создаем словарь с данными для резервной копии
    backup_data = {
        'users': users_db,
        'groups': groups_db,
        'tests': tests_db,
        'results': test_results_db,
        'backup_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    
    # Преобразуем данные в JSON
    backup_json = json.dumps(backup_data, indent=4, default=str)
    
    # Создаем объект ответа с JSON-данными
    response = make_response(backup_json)
    response.headers['Content-Type'] = 'application/json'
    response.headers['Content-Disposition'] = f'attachment; filename=edu_system_backup_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
    
    return response

# СТУДЕНЧЕСКАЯ ПАНЕЛЬ
@app.route('/student/dashboard')
def student_dashboard():
    if 'logged_in' not in session or not session['logged_in'] or session['role'] != 'student':
        flash('У вас нет доступа к этой странице', 'danger')
        return redirect(url_for('login'))
    
    username = session['username']
    
    # Находим группы студента
    student_groups = []
    for group_id, group_info in groups_db.items():
        if username in group_info['students']:
            student_groups.append({
                "id": group_id,
                "name": group_info['name']
            })
    
    # Находим доступные тесты
    available_tests = []
    for test_id, test_info in tests_db.items():
        # Проверяем формат assigned_to и действуем соответственно
        if isinstance(test_info['assigned_to'], list):
            # Старый формат: список group_id
            for group_id in test_info['assigned_to']:
                if any(group['id'] == group_id for group in student_groups):
                    available_tests.append({
                        "id": test_id,
                        "title": test_info['title'],
                        "description": test_info['description']
                    })
                    break
        else:
            # Новый формат: словарь с groups и students
            # Проверяем, назначен ли тест конкретно этому студенту
            if username in test_info['assigned_to'].get('students', []):
                available_tests.append({
                    "id": test_id,
                    "title": test_info['title'],
                    "description": test_info['description']
                })
                continue
                
            # Проверяем группы студента
            for group_id in test_info['assigned_to'].get('groups', []):
                if any(group['id'] == group_id for group in student_groups):
                    available_tests.append({
                        "id": test_id,
                        "title": test_info['title'],
                        "description": test_info['description']
                    })
                    break
    
    return render_template('student/dashboard.html', 
                          username=username,
                          role=session['role'],
                          groups=student_groups,
                          tests=available_tests)

@app.route('/student/tests')
def student_tests():
    if 'logged_in' not in session or not session['logged_in'] or session['role'] != 'student':
        flash('У вас нет доступа к этой странице', 'danger')
        return redirect(url_for('login'))
    
    username = session['username']
    
    # Находим тесты, доступные для студента
    available_tests = []
    
    for test_id, test_data in tests_db.items():
        # Проверяем, назначен ли тест студенту лично или его группе
        assigned_to = test_data.get('assigned_to', {})
        if isinstance(assigned_to, list):  # Защита от ошибки, если assigned_to это список
            assigned_to = {'students': [], 'groups': []}
            
        is_assigned_personally = username in assigned_to.get('students', [])
        
        # Проверяем, назначен ли тест группе студента
        is_assigned_to_group = False
        for group_id, group_data in groups_db.items():
            if username in group_data.get('students', []) and group_id in assigned_to.get('groups', []):
                is_assigned_to_group = True
                break
        
        # Если тест назначен и видимый (не является черновиком)
        if (is_assigned_personally or is_assigned_to_group) and test_data.get('visibility', 'draft') != 'draft':
            # Проверяем, не проходил ли студент уже этот тест
            already_taken = False
            result_data = None
            for result_id, result in test_results_db.items():
                if result.get('user_id') == username and result.get('test_id') == test_id:
                    already_taken = True
                    result_data = result
                    break
            
            test_info = {
                "id": test_id,
                "title": test_data.get('title', 'Без названия'),
                "description": test_data.get('description', ''),
                "category": test_data.get('category', 'Общие'),
                "questions_count": len(test_data.get('questions', [])),
                "time_limit": test_data.get('time_limit', 45),
                "max_score": sum(q.get('points', 10) for q in test_data.get('questions', [])),
                "already_taken": already_taken
            }
            
            # Если тест пройден, добавляем данные о результате
            if result_data:
                test_info["result_data"] = {
                    "score": result_data.get('score', 0),
                    "max_score": result_data.get('max_score', 0),
                    "grade": result_data.get('grade', 2),
                    "completion_date": result_data.get('completion_date', 0),
                    "result_id": list(test_results_db.keys())[list(test_results_db.values()).index(result_data)]
                }
            
            available_tests.append(test_info)
    
    # Если в базе тестов пока мало, добавим демо-тест для демонстрации
    if not available_tests:
        available_tests = [
            {
                "id": "demo_test",
                "title": "Основы программирования",
                "description": "Проверка базовых знаний и навыков по программированию",
                "category": "Программирование",
                "questions_count": 10,
                "time_limit": 45,
                "max_score": 100,
                "already_taken": False
            }
        ]
    
    return render_template('student/tests.html', 
                          username=session['username'],
                          role=session['role'],
                          tests=available_tests)

@app.route('/student/tests/take/<test_id>')
def student_take_test(test_id):
    if 'logged_in' not in session or not session['logged_in'] or session['role'] != 'student':
        flash('У вас нет доступа к этой странице', 'danger')
        return redirect(url_for('login'))
    
    username = session['username']
    
    # Проверка, не проходил ли студент этот тест ранее
    existing_result = None
    for result_id, result in test_results_db.items():
        if result['user_id'] == username and result['test_id'] == test_id:
            existing_result = result
            break
    
    if existing_result:
        flash('Тест уже пройден! Переход к результатам.', 'info')
        result_id = list(test_results_db.keys())[list(test_results_db.values()).index(existing_result)]
        return redirect(url_for('student_test_result', result_id=result_id))
    
    # Проверяем наличие теста
    if test_id not in tests_db and test_id != "demo_test":
        flash('Тест не найден', 'danger')
        return redirect(url_for('student_tests'))
    
    # Проверяем доступность теста
    test_data = tests_db.get(test_id, {})
    
    # Проверяем доступ студента к тесту
    if test_id != "demo_test":
        # Получаем группы студента
        student_groups = []
        for group_id, group_info in groups_db.items():
            if username in group_info.get('students', []):
                student_groups.append(group_id)
        
        # Проверяем, назначен ли тест студенту или его группе
        assigned_to = test_data.get('assigned_to', {})
        if isinstance(assigned_to, list):  # Старый формат
            is_assigned = any(group_id in assigned_to for group_id in student_groups)
        else:  # Новый формат
            is_assigned_personally = username in assigned_to.get('students', [])
            is_assigned_to_group = any(group_id in assigned_to.get('groups', []) for group_id in student_groups)
            is_assigned = is_assigned_personally or is_assigned_to_group
        
        # Проверяем, опубликован ли тест
        is_published = test_data.get('visibility', 'draft') != 'draft'
        
        if not (is_assigned and is_published):
            flash('У вас нет доступа к этому тесту', 'danger')
            return redirect(url_for('student_tests'))
    
    # Если демо-тест, создаем тестовые данные
    if test_id == "demo_test":
        test_data = {
            "id": "demo_test",
            "title": "Основы программирования",
            "description": "Проверка базовых знаний и навыков по программированию",
            "category": "Программирование",
            "time_limit": 45,
            "questions": [
                {
                    "id": "q1",
                    "text": "Что такое переменная в программировании?",
                    "type": "single",
                    "points": 10,
                    "options": [
                        {"text": "Контейнер для хранения данных", "is_correct": True},
                        {"text": "Функция выполняющая вычисления", "is_correct": False},
                        {"text": "Оператор управления потоком", "is_correct": False},
                        {"text": "Тип данных", "is_correct": False}
                    ]
                },
                {
                    "id": "q2",
                    "text": "Какие из следующих типов данных относятся к примитивным?",
                    "type": "multiple",
                    "points": 20,
                    "options": [
                        {"text": "Целые числа (int)", "is_correct": True},
                        {"text": "Строки (string)", "is_correct": True},
                        {"text": "Списки (list)", "is_correct": False},
                        {"text": "Словари (dict)", "is_correct": False},
                        {"text": "Логические значения (boolean)", "is_correct": True}
                    ]
                },
                {
                    "id": "q3",
                    "text": "Напишите команду для вывода текста 'Hello, World!' в консоль на языке Python.",
                    "type": "text",
                    "points": 15,
                    "correct_answer": "print(\"Hello, World!\")"
                }
            ]
        }
    
    # Проверяем на ранее пройденный тест
    for result_id, result_data in test_results_db.items():
        if result_data.get('user_id') == username and result_data.get('test_id') == test_id:
            flash('Вы уже проходили этот тест', 'warning')
            return redirect(url_for('student_tests'))
    
    # Преобразуем структуру вопросов в формат, подходящий для шаблона
    if 'questions' in test_data and test_id != "demo_test":
        processed_questions = []
        
        for i, q in enumerate(test_data['questions']):
            # Создаем новый формат вопроса
            processed_question = {
                'id': f"q{i+1}",
                'text': q.get('text', q.get('question', 'Без текста вопроса')),
                'points': q.get('points', 10),  # По умолчанию 10 баллов
                'options': [],
                'correct_answer': q.get('correct_answer', 0)
            }
            
            # Определение типа вопроса и обработка вариантов ответа
            if 'options' in q and len(q['options']) > 0:
                # Если варианты ответов уже в формате списка объектов с полями text и is_correct
                if isinstance(q.get('options', [])[0], dict) and 'text' in q.get('options', [])[0]:
                    # Обрабатываем существующие варианты, предотвращая вложенность
                    options = []
                    
                    for opt in q['options']:
                        # Проверяем, нет ли вложенности в поле 'text'
                        if isinstance(opt.get('text'), dict) and 'text' in opt.get('text', {}):
                            # Убираем одну вложенность
                            clean_option = {
                                'text': opt['text'].get('text', 'Вариант ответа'),
                                'is_correct': opt.get('is_correct', False)
                            }
                            options.append(clean_option)
                        else:
                            # Просто добавляем вариант без изменений
                            options.append({
                                'text': opt.get('text', 'Вариант ответа'),
                                'is_correct': opt.get('is_correct', False)
                            })
                    
                    # Определяем тип вопроса на основе вариантов ответа
                    correct_count = sum(1 for opt in options if opt.get('is_correct', False))
                    if correct_count > 1:
                        processed_question['type'] = 'multiple'
                    else:
                        processed_question['type'] = 'single'
                    
                    # Используем очищенные опции
                    processed_question['options'] = options
                else:
                    # Для обратной совместимости - варианты как список строк
                    if isinstance(q.get('correct_answer'), list):
                        processed_question['type'] = 'multiple'
                        # Преобразуем опции в нужный формат для множественного выбора
                        processed_question['options'] = [{"text": opt, "is_correct": i in q['correct_answer']} 
                                                for i, opt in enumerate(q['options'])]
                    else:
                        processed_question['type'] = 'single'
                        correct_idx = q.get('correct_answer', 0)
                        # Преобразуем опции для одиночного выбора
                        processed_question['options'] = [{"text": opt, "is_correct": i == correct_idx} 
                                                for i, opt in enumerate(q['options'])]
            else:
                processed_question['type'] = 'text'
                processed_question['correct_answer'] = q.get('correct_answer', '')
            
            processed_questions.append(processed_question)
            
        test_data['questions'] = processed_questions
        
        # Рассчитываем максимальное количество баллов в тесте
        max_score = sum(q.get('points', 10) for q in processed_questions)
        test_data['max_score'] = max_score
    
    # Устанавливаем время начала теста
    session['test_start_time'] = time.time()
    
    return render_template('student/take_test.html',
                          username=username,
                          role=session['role'],
                          test=test_data)

@app.route('/student/tests/submit/<test_id>', methods=['POST'])
@app.route('/student/tests/submit', methods=['POST'])
@app.route('/student/submit_test/<test_id>', methods=['POST'])
@app.route('/student/submit_test', methods=['POST'])
def student_submit_test(test_id=None):
    """Функция обработки отправки теста студентом"""
    print("=" * 50)
    print(f"ОТЛАДКА: Начало обработки отправки теста")
    print(f"ОТЛАДКА: Форма содержит {len(request.form)} полей")
    print(f"ОТЛАДКА: Поля формы: {list(request.form.keys())}")
    
    # Проверка аутентификации
    if 'logged_in' not in session or not session['logged_in'] or session['role'] != 'student':
        print("Ошибка аутентификации при отправке теста")
        flash('У вас нет доступа к этой странице', 'danger')
        return redirect(url_for('login'))
    
    username = session['username']
    
    # Определение ID теста
    if test_id is None:
        test_id = request.form.get('test_id')
        print(f"ID теста из формы: {test_id}")
    
    if not test_id and "demo_test" in request.path:
        test_id = "demo_test"
        
    print(f"Получен запрос на отправку теста с ID: {test_id}")
    print(f"Пользователь {username} отправляет тест {test_id}")
    
    # Проверка наличия ID теста
    if not test_id:
        print("ID теста не указан")
        flash('Ошибка: ID теста не указан', 'danger')
        return redirect(url_for('student_tests'))
    
    # Проверка существования теста
    if test_id not in tests_db and test_id != "demo_test":
        print(f"Тест с ID {test_id} не найден в базе данных")
        flash('Тест не найден', 'danger')
        return redirect(url_for('student_tests'))
    
    # Проверка, не проходил ли студент этот тест ранее
    existing_result = None
    for result_id, result in test_results_db.items():
        if result['user_id'] == username and result['test_id'] == test_id:
            existing_result = result
            break
    
    if existing_result:
        print(f"Студент {username} уже проходил тест {test_id}")
        flash('Вы уже проходили этот тест. Повторное прохождение невозможно.', 'warning')
        return redirect(url_for('student_test_result', result_id=list(test_results_db.keys())[list(test_results_db.values()).index(existing_result)]))

    # Получение данных теста
    if test_id == "demo_test":
        test_data = {
            "id": "demo_test",
            "title": "Демо-тест",
            "description": "Проверка базовых знаний и навыков по программированию",
            "category": "Программирование",
            "time_limit": 45,
            "questions": [
                {
                    "id": "q1",
                    "text": "Что такое переменная в программировании?",
                    "type": "single",
                    "points": 10,
                    "options": [
                        {"text": "Контейнер для хранения данных", "is_correct": True},
                        {"text": "Функция выполняющая вычисления", "is_correct": False},
                        {"text": "Оператор управления потоком", "is_correct": False},
                        {"text": "Тип данных", "is_correct": False}
                    ]
                },
                {
                    "id": "q2",
                    "text": "Какие из следующих типов данных относятся к примитивным?",
                    "type": "multiple",
                    "points": 20,
                    "options": [
                        {"text": "Целые числа (int)", "is_correct": True},
                        {"text": "Строки (string)", "is_correct": True},
                        {"text": "Списки (list)", "is_correct": False},
                        {"text": "Словари (dict)", "is_correct": False},
                        {"text": "Логические значения (boolean)", "is_correct": True}
                    ]
                }
            ]
        }
    else:
        test_data = tests_db.get(test_id, {})
    
    # Получаем данные о начале прохождения теста
    start_time_str = request.form.get('start_time')
    
    if not start_time_str:
        print("Время начала теста не указано")
        flash('Ошибка: время начала теста не указано', 'danger')
        return redirect(url_for('student_tests'))
    
    try:
        start_time = datetime.strptime(start_time_str, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        print(f"Некорректный формат времени начала теста: {start_time_str}")
        flash('Ошибка: некорректный формат времени начала теста', 'danger')
        return redirect(url_for('student_tests'))
    
    # Вычисляем время, потраченное на тест
    current_time = datetime.now()
    time_elapsed = (current_time - start_time).total_seconds() / 60  # в минутах
    time_spent = int((current_time - start_time).total_seconds())  # в секундах для сохранения
    print(f"ОТЛАДКА: Время начала: {start_time}, текущее время: {current_time}, затрачено: {time_spent} сек.")
    
    # Проверяем, не истекло ли время на выполнение теста
    time_limit_minutes = test_data.get('time_limit', 45)
    if time_elapsed > time_limit_minutes + 2:  # Добавляем небольшой запас времени
        print(f"Время на выполнение теста истекло. Прошло {time_elapsed:.2f} минут из {time_limit_minutes}")
        flash('Время на выполнение теста истекло', 'warning')
        return redirect(url_for('student_tests'))
    
    # Обрабатываем ответы студента
    print("-" * 50)
    print("ОТЛАДКА: Начало обработки ответов студента")
    print(f"ОТЛАДКА: Тест содержит {len(test_data.get('questions', []))} вопросов")
    
    score = 0
    max_score = 0
    correct_answers = 0
    incorrect_answers = 0
    detailed_results = []
    
    for question in test_data.get('questions', []):
        question_id = question.get('id')
        question_text = question.get('text')
        question_type = question.get('type')
        question_points = question.get('points', 10)
        max_score += question_points
        
        print(f"ОТЛАДКА: Обработка вопроса {question_id} типа {question_type}, стоимость {question_points} баллов")
        
        # Обработка разных типов вопросов
        if question_type == 'single':
            # Получаем индекс выбранного варианта
            selected_option_idx = request.form.get(f'question_{question_id}', None)
            print(f"ОТЛАДКА: Получен ответ из формы для вопроса {question_id}: {selected_option_idx}")
            
            # Получаем правильный вариант и ответ студента
            correct_option_text = ""
            student_answer_text = "Не отвечено"
            is_correct = False
            
            # Если студент выбрал вариант
            if selected_option_idx is not None:
                selected_option_idx = int(selected_option_idx)
                if 0 <= selected_option_idx < len(question.get('options', [])):
                    student_answer_text = question['options'][selected_option_idx]['text']
                    
                    # Проверяем, правильный ли это вариант
                    is_correct = question['options'][selected_option_idx].get('is_correct', False)
                    
                    # Находим текст правильного варианта
                    for i, option in enumerate(question.get('options', [])):
                        if option.get('is_correct', False):
                            correct_option_text = option.get('text', '')
                            break
                    
                    if is_correct:
                        score += question_points
                        correct_answers += 1
                    else:
                        incorrect_answers += 1
                else:
                    incorrect_answers += 1
            else:
                incorrect_answers += 1
            
            # Добавляем результат вопроса
            detailed_results.append({
                'question_id': question_id,
                'question_text': question_text,
                'student_answer': student_answer_text,
                'correct_answer': correct_option_text,
                'is_correct': is_correct,
                'points_earned': question_points if is_correct else 0,
                'max_points': question_points
            })
            
        elif question_type == 'multiple':
            # Получаем индексы выбранных вариантов
            selected_options = request.form.getlist(f'question_{question_id}[]')
            selected_indices = [int(idx) for idx in selected_options if idx.isdigit()]
            
            # Считаем правильные и неправильные ответы
            correct_option_indices = [i for i, option in enumerate(question.get('options', [])) if option.get('is_correct', False)]
            correct_option_texts = [option.get('text', '') for i, option in enumerate(question.get('options', [])) if option.get('is_correct', False)]
            
            # Формируем текст ответа студента
            if selected_indices:
                student_answer_text = ", ".join([question['options'][idx]['text'] for idx in selected_indices if 0 <= idx < len(question.get('options', []))])
            else:
                student_answer_text = "Не отвечено"
            
            # Проверяем правильность ответа
            is_correct = set(selected_indices) == set(correct_option_indices)
            
            # Частичное начисление баллов для множественного выбора
            if is_correct:
                score += question_points
                correct_answers += 1
            else:
                # Частичное начисление баллов, если выбраны не все правильные ответы
                correct_selected = sum(1 for idx in selected_indices if idx in correct_option_indices)
                incorrect_selected = sum(1 for idx in selected_indices if idx not in correct_option_indices)
                
                if correct_selected > 0 and incorrect_selected == 0:
                    # Если выбраны только правильные варианты, но не все
                    partial_score = (correct_selected / len(correct_option_indices)) * question_points
                    score += partial_score
                
                incorrect_answers += 1
            
            # Добавляем результат вопроса
            detailed_results.append({
                'question_id': question_id,
                'question_text': question_text,
                'student_answer': student_answer_text,
                'correct_answer': ", ".join(correct_option_texts),
                'is_correct': is_correct,
                'points_earned': question_points if is_correct else 0,
                'max_points': question_points
            })
            
        elif question_type == 'text':
            # Получаем текстовый ответ студента
            student_answer = request.form.get(f'question_{question_id}', '').strip()
            correct_answer = question.get('correct_answer', '').strip()
            
            # Проверяем правильность ответа (без учета регистра)
            is_correct = student_answer.lower() == correct_answer.lower()
            
            if is_correct:
                score += question_points
                correct_answers += 1
            else:
                incorrect_answers += 1
            
            # Добавляем результат вопроса
            detailed_results.append({
                'question_id': question_id,
                'question_text': question_text,
                'student_answer': student_answer if student_answer else "Не отвечено",
                'correct_answer': correct_answer,
                'is_correct': is_correct,
                'points_earned': question_points if is_correct else 0,
                'max_points': question_points
            })
    
    # Вычисляем процент правильных ответов
    if max_score > 0:
        percent = (score / max_score) * 100
    else:
        percent = 0
    
    # Округляем процент до десятых
    percent = round(percent * 10) / 10
    
    print(f"Результат теста: {score}/{max_score} ({percent}%) - правильных: {correct_answers}, неправильных: {incorrect_answers}")
    
    # Вычисляем оценку на основе процента
    if percent >= 90:
        grade = 5.0
    elif percent >= 75:
        grade = 4.0 + (percent - 75) / 15
    elif percent >= 60:
        grade = 3.0 + (percent - 60) / 15
    else:
        grade = 2.0 + (percent - 0) / 60 if percent > 0 else 2.0
    
    # Округляем до десятых
    grade = round(grade * 10) / 10
    
    # Создаем уникальный ID для результата
    result_id = f"result_{int(time.time())}_{username}_{secrets.token_hex(4)}"
    print(f"ОТЛАДКА: Создан новый ID результата: {result_id}")
    
    # Сохраняем результат теста
    test_results_db[result_id] = {
        'user_id': username,
        'test_id': test_id,
        'test_title': test_data.get('title', 'Без названия'),
        'category': test_data.get('category', 'Общие'),
        'score': score,
        'max_score': max_score,
        'percent': percent,
        'grade': grade,
        'completion_date': time.time(),
        'time_spent': time_spent,  # Используем вычисленное время из строки 1050
        'correct_answers': correct_answers,
        'incorrect_answers': incorrect_answers,
        'total_questions': len(test_data.get('questions', [])),
        'detailed_results': detailed_results
    }
    
    print(f"ОТЛАДКА: Результат сохранен. Перенаправление на страницу результата: {result_id}")
    
    # Перенаправляем на страницу с результатами
    return redirect(url_for('student_test_result', result_id=result_id))

@app.route('/student/results')
def student_results():
    if 'logged_in' not in session or not session['logged_in'] or session['role'] != 'student':
        flash('У вас нет доступа к этой странице', 'danger')
        return redirect(url_for('login'))
    
    username = session['username']
    
    # Находим все результаты тестов для студента
    student_results = []
    for result_id, result_data in test_results_db.items():
        if result_data.get('user_id') == username:
            student_results.append({
                'id': result_id,
                'test_title': result_data.get('test_title', 'Без названия'),
                'category': result_data.get('category', 'Общие'),
                'score': result_data.get('score', 0),
                'max_score': result_data.get('max_score', 100),
                'grade': result_data.get('grade', 2.0),
                'correct_answers': result_data.get('correct_answers', 0),
                'total_questions': result_data.get('total_questions', 0),
                'completion_date': result_data.get('completion_date', time.time())
            })
    
    # Сортируем результаты по дате (сначала новые)
    student_results.sort(key=lambda x: x.get('completion_date', 0), reverse=True)
    
    # Рассчитываем статистику
    if student_results:
        avg_grade = sum(result.get('grade', 0) for result in student_results) / len(student_results)
        avg_percent = sum((result.get('score', 0) / result.get('max_score', 100)) * 100 for result in student_results) / len(student_results)
    else:
        avg_grade = 0
        avg_percent = 0
    
    stats = {
        'tests_completed': len(student_results),
        'average_grade': avg_grade,
        'average_percent': avg_percent
    }
    
    return render_template('student/results.html',
                          username=username,
                          role=session['role'],
                          results=student_results,
                          stats=stats)

@app.route('/student/results/<result_id>')
def student_test_result(result_id):
    print(f"ОТЛАДКА: Запрос на отображение результата с ID {result_id}")
    
    if 'logged_in' not in session or not session['logged_in'] or session['role'] != 'student':
        print(f"ОТЛАДКА: Ошибка аутентификации при просмотре результата")
        flash('У вас нет доступа к этой странице', 'danger')
        return redirect(url_for('login'))
    
    username = session['username']
    
    # Проверяем наличие результата и доступ к нему
    if result_id not in test_results_db or test_results_db[result_id].get('user_id') != username:
        flash('Результат не найден или у вас нет к нему доступа', 'danger')
        return redirect(url_for('student_results'))
    
    # Получаем данные результата
    result = test_results_db[result_id]
    
    return render_template('student/test_results.html',
                          username=username,
                          role=session['role'],
                          result=result,
                          time=time)

# ПАНЕЛЬ ПРЕПОДАВАТЕЛЯ
@app.route('/teacher/dashboard')
def teacher_dashboard():
    if 'logged_in' not in session or not session['logged_in'] or session['role'] != 'teacher':
        flash('У вас нет доступа к этой странице', 'danger')
        return redirect(url_for('login'))
    
    username = session['username']
    
    # Находим тесты преподавателя
    teacher_tests = []
    for test_id, test_info in tests_db.items():
        if test_info['created_by'] == username:
            teacher_tests.append({
                "id": test_id,
                "title": test_info['title'],
                "questions_count": len(test_info['questions']),
                "assigned_to": test_info['assigned_to']
            })
    
    return render_template('teacher/dashboard.html', 
                          username=username,
                          role=session['role'],
                          tests=teacher_tests,
                          groups=groups_db)

@app.route('/teacher/tests')
def teacher_tests():
    if 'logged_in' not in session or not session['logged_in'] or session['role'] != 'teacher':
        flash('У вас нет доступа к этой странице', 'danger')
        return redirect(url_for('login'))
    
    username = session['username']
    
    # Находим тесты преподавателя и подготавливаем полные данные для отображения
    teacher_tests = []
    for test_id, test_info in tests_db.items():
        if test_info['created_by'] == username:
            # Копируем тест полностью, чтобы сохранить все данные, включая вопросы и ответы
            test_copy = test_info.copy()
            test_copy["id"] = test_id
            teacher_tests.append(test_copy)
    
    return render_template('teacher/tests.html', 
                          username=username,
                          role=session['role'],
                          tests=teacher_tests)

@app.route('/teacher/tests/new')
def teacher_new_test():
    if 'logged_in' not in session or not session['logged_in'] or session['role'] != 'teacher':
        flash('У вас нет доступа к этой странице', 'danger')
        return redirect(url_for('login'))
    
    return render_template('teacher/new_create_test.html',
                          username=session['username'],
                          role=session['role'])

@app.route('/teacher/analytics')
def teacher_analytics():
    if 'logged_in' not in session or not session['logged_in'] or session['role'] != 'teacher':
        flash('У вас нет доступа к этой странице', 'danger')
        return redirect(url_for('login'))
    
    username = session['username']
    
    # Заглушка для данных аналитики
    analytics_data = {
        "average_score": 4.2,
        "completed_tests": 12,
        "students_count": 5
    }
    
    return render_template('teacher/analytics.html', 
                          username=username,
                          role=session['role'],
                          analytics=analytics_data)

@app.route('/teacher/assign')
def teacher_assign():
    if 'logged_in' not in session or not session['logged_in'] or session['role'] != 'teacher':
        flash('У вас нет доступа к этой странице', 'danger')
        return redirect(url_for('login'))
    
    username = session['username']
    
    # Находим тесты преподавателя
    teacher_tests = []
    for test_id, test_info in tests_db.items():
        if test_info['created_by'] == username:
            teacher_tests.append({
                "id": test_id,
                "title": test_info['title']
            })
    
    return render_template('teacher/assign.html', 
                          username=username,
                          role=session['role'],
                          tests=teacher_tests,
                          groups=groups_db)
                          
# Маршрут для отображения формы создания теста
@app.route('/teacher/create_test', methods=['GET'])
def teacher_create_test():
    if 'logged_in' not in session or not session['logged_in'] or session['role'] != 'teacher':
        flash('У вас нет доступа к этой странице', 'danger')
        return redirect(url_for('login'))
    
    # Отображаем форму создания теста
    return render_template('teacher/create_test.html',
                          username=session['username'],
                          role=session['role'])

@app.route('/teacher/tests/save', methods=['POST'])
def teacher_save_test():
    """Функция для сохранения нового теста или обновления существующего, созданного преподавателем"""
    if 'logged_in' not in session or not session['logged_in'] or session['role'] != 'teacher':
        flash('У вас нет доступа к этой странице', 'danger')
        return redirect(url_for('login'))
    
    try:
        logging.info("=" * 50)
        logging.info("Запрос на сохранение теста через форму")
        
        # Получаем данные из формы
        form_data = request.form.to_dict()
        logging.info(f"Получены данные формы: {form_data}")
        
        # Получаем ID теста (для редактирования) или создаем новый
        test_id = form_data.get('test_id')
        if not test_id or test_id not in tests_db:
            test_id = f"test_{int(time.time())}"
            logging.info(f"Создан новый ID теста: {test_id}")
        else:
            logging.info(f"Редактирование существующего теста с ID: {test_id}")
            # Проверяем права доступа к существующему тесту
            if tests_db[test_id]['created_by'] != session['username'] and session['role'] != 'admin':
                flash('У вас нет прав для редактирования этого теста', 'danger')
                return redirect(url_for('teacher_tests'))
        
        # Получаем данные о вопросах из JSON
        questions_json = form_data.get('questions_data', '[]')
        questions = json.loads(questions_json)
        logging.info(f"Получено {len(questions)} вопросов")
        
        # Собираем данные теста
        title = form_data.get('title', '').strip()
        description = form_data.get('description', '').strip()
        duration = int(form_data.get('duration', 30))
        passing_score = int(form_data.get('passing_score', 70))
        category = form_data.get('category', 'all')
        
        # Валидация основных данных
        if not title:
            flash('Название теста обязательно', 'danger')
            return redirect(url_for('teacher_tests'))
        
        # Формируем данные теста для сохранения
        test_data = {
            "id": test_id,
            "title": title,
            "description": description,
            "category": category,
            "duration": duration,
            "passing_score": passing_score,
            "visibility": "draft",
            "questions": questions,
            "questions_count": len(questions),
            "created_by": session['username'],
            "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "assigned_to": {"groups": [], "students": []}
        }
        
        # Сохраняем тест в базе данных
        tests_db[test_id] = test_data
        
        flash(f'Тест "{title}" успешно сохранен!', 'success')
        return redirect(url_for('teacher_tests'))
    
    except Exception as e:
        logging.error("=" * 50)
        logging.error(f"Ошибка при сохранении теста: {str(e)}")
        traceback.print_exc()
        logging.error("=" * 50)
        
        flash('Произошла ошибка при сохранении теста', 'danger')
        return redirect(url_for('teacher_tests'))

@app.route('/api/tests/create', methods=['POST'])
def api_tests_create():
    """API-эндпоинт для создания тестов"""
    # Проверка авторизации
    if 'logged_in' not in session or not session['logged_in'] or session['role'] != 'teacher':
        return jsonify({
            'status': 'error',
            'message': 'Отказано в доступе. Требуется роль преподавателя.'
        }), 403
    
    try:
        logging.info("=" * 50)
        logging.info("Запрос на создание теста через API")
        
        # Получаем данные из JSON-запроса
        if request.is_json:
            data = request.get_json()
            logging.info(f"Получены JSON данные: {json.dumps(data, ensure_ascii=False)[:200]}...")
        else:
            # Обработка формы для совместимости
            form_data = request.form.to_dict()
            logging.info(f"Получены данные формы: {form_data}")
            
            # Преобразуем данные формы в JSON-структуру
            try:
                questions_json = form_data.get('questions_data', '[]')
                questions = json.loads(questions_json)
                
                data = {
                    'title': form_data.get('title', form_data.get('test_title', '')).strip(),
                    'description': form_data.get('description', form_data.get('test_description', '')).strip(),
                    'time_limit': int(form_data.get('time_limit', form_data.get('test_time_limit', 30))),
                    'passing_score': int(form_data.get('passing_score', form_data.get('test_passing_score', 70))),
                    'status': form_data.get('status', form_data.get('test_visibility', 'draft')),
                    'questions': questions
                }
            except json.JSONDecodeError as e:
                logging.error(f"Ошибка декодирования JSON: {e}")
                return jsonify({
                    'status': 'error',
                    'message': 'Ошибка в формате данных вопросов'
                }), 400
        
        # Валидация данных
        validation_errors = []
        
        # 1. Проверка основных полей
        if not data.get('title'):
            validation_errors.append('Название теста обязательно')
        
        # 2. Проверка вопросов
        questions = data.get('questions', [])
        if not questions:
            validation_errors.append('Тест должен содержать хотя бы один вопрос')
        
        # 3. Проверка каждого вопроса
        for i, question in enumerate(questions):
            q_num = i + 1
            
            # Проверка наличия текста вопроса
            if not question.get('text'):
                validation_errors.append(f'Вопрос {q_num}: отсутствует текст вопроса')
                continue
            
            # Проверка типа вопроса
            q_type = question.get('type')
            if q_type not in ['single', 'multiple', 'text']:
                validation_errors.append(f'Вопрос {q_num}: недопустимый тип вопроса')
                continue
            
            # Проверки в зависимости от типа вопроса
            if q_type == 'text':
                # Для текстовых вопросов обязателен правильный ответ
                if not question.get('correct_answer'):
                    validation_errors.append(f'Вопрос {q_num}: не указан правильный ответ')
            else:
                # Для вопросов с вариантами
                options = question.get('options', [])
                
                # Минимум 2 варианта ответа
                if len(options) < 2:
                    validation_errors.append(f'Вопрос {q_num}: должно быть не менее 2 вариантов ответа')
                    continue
                
                # Проверка наличия правильного ответа
                has_correct = any(opt.get('is_correct') for opt in options)
                if not has_correct:
                    validation_errors.append(f'Вопрос {q_num}: не выбран правильный ответ')
                
                # Проверка наличия текста в вариантах
                for j, option in enumerate(options):
                    if not option.get('text'):
                        validation_errors.append(f'Вопрос {q_num}, вариант {j+1}: пустой текст варианта')
        
        # Если есть ошибки валидации, возвращаем их
        if validation_errors:
            logging.error(f"Ошибки валидации: {validation_errors}")
            return jsonify({
                'status': 'error',
                'message': 'Ошибки в данных теста',
                'errors': validation_errors
            }), 400
        
        # Создание теста
        test_id = f"test_{int(time.time())}_{secrets.token_hex(4)}"
        
        # Формируем данные теста для сохранения
        test_data = {
            "id": test_id,
            "title": data['title'],
            "description": data.get('description', ''),
            "category": data.get('category', 'all'),
            "time_limit": data.get('time_limit', 30),
            "passing_score": data.get('passing_score', 70),
            "visibility": data.get('status', 'draft'),
            "questions": questions,
            "questions_count": len(questions),
            "created_by": session['username'],
            "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "assigned_to": {"groups": [], "students": []}
        }
        
        # Сохраняем тест в базе данных
        tests_db[test_id] = test_data
        
        logging.info(f"Тест успешно создан! ID: {test_id}")
        logging.info("=" * 50)
        
        # Определяем тип ответа (JSON или редирект)
        if request.is_json:
            return jsonify({
                'status': 'success',
                'message': f'Тест "{data["title"]}" успешно создан',
                'test_id': test_id
            }), 201
        else:
            flash(f'Тест "{data["title"]}" успешно создан!', 'success')
            return redirect(url_for('teacher_tests'))
    
    except Exception as e:
        logging.error("=" * 50)
        logging.error(f"Ошибка при создании теста: {str(e)}")
        traceback.print_exc()
        logging.error("=" * 50)
        
        if request.is_json:
            return jsonify({
                'status': 'error',
                'message': 'Произошла ошибка при создании теста',
                'error': str(e)
            }), 500
        else:
            flash('Произошла ошибка при создании теста', 'danger')
            return redirect(url_for('teacher_new_test'))
    
# Маршрут для редактирования теста
@app.route('/teacher/tests/edit/<test_id>', methods=['GET', 'POST'])
def teacher_edit_test(test_id):
    if 'logged_in' not in session or not session['logged_in'] or session['role'] != 'teacher':
        flash('У вас нет доступа к этой странице', 'danger')
        return redirect(url_for('login'))
    
    # Проверка существования теста и прав доступа
    if test_id not in tests_db or tests_db[test_id]['created_by'] != session['username']:
        flash('Тест не найден или у вас нет прав для его редактирования', 'danger')
        return redirect(url_for('teacher_tests'))
    
    # Если GET-запрос, отображаем форму редактирования
    if request.method == 'GET':
        test_data = tests_db[test_id].copy()  # Создаем копию, чтобы не менять оригинал
        
        # Для корректного отображения вопросов
        if 'questions' in test_data:
            # Для дебага: печатаем структуру вопросов
            print(f"Структура вопросов в тесте: {test_data['questions'][:2]}")
            
            # Преобразуем вопросы в JSON для передачи в шаблон
            questions_json = json.dumps(test_data.get('questions', []))
            print(f"JSON вопросов для шаблона: {questions_json[:100]}...")
        else:
            questions_json = "[]"
            print("Вопросы отсутствуют в тесте!")
        
        return render_template('teacher/edit_test.html', 
                              username=session['username'],
                              role=session['role'],
                              test=test_data,
                              test_id=test_id,
                              questions_json=questions_json)
    
    # Получаем данные формы
    title = request.form.get('title', '')
    description = request.form.get('description', '')
    category = request.form.get('category', '')
    time_limit = request.form.get('time_limit', 45)
    visibility = request.form.get('visibility', 'draft')
    
    # Получаем данные о вопросах из JSON
    questions_data = request.form.get('questions_data', '[]')
    try:
        questions = json.loads(questions_data)
    except json.JSONDecodeError:
        questions = []
    
    # Валидация основных данных
    if not title:
        flash('Название теста обязательно', 'danger')
        return redirect(url_for('teacher_tests'))
    
    # Обновляем тест
    tests_db[test_id]['title'] = title
    tests_db[test_id]['description'] = description
    tests_db[test_id]['category'] = category
    tests_db[test_id]['time_limit'] = int(time_limit)
    tests_db[test_id]['visibility'] = visibility
    tests_db[test_id]['questions'] = questions
    tests_db[test_id]['questions_count'] = len(questions)
    tests_db[test_id]['updated_at'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    flash(f'Тест "{title}" успешно обновлен', 'success')
    return redirect(url_for('teacher_tests'))
    
# Маршрут для удаления теста
@app.route('/teacher/tests/delete/<test_id>', methods=['POST'])
def teacher_delete_test(test_id):
    if 'logged_in' not in session or not session['logged_in'] or session['role'] != 'teacher':
        flash('У вас нет доступа к этой странице', 'danger')
        return redirect(url_for('login'))
    
    # Проверка существования теста и прав доступа
    if test_id not in tests_db or tests_db[test_id]['created_by'] != session['username']:
        flash('Тест не найден или у вас нет прав для его удаления', 'danger')
        return redirect(url_for('teacher_tests'))
    
    # Получаем название теста для сообщения
    test_title = tests_db[test_id]['title']
    
    # Удаляем тест
    del tests_db[test_id]
    
    flash(f'Тест "{test_title}" успешно удален', 'success')
    return redirect(url_for('teacher_tests'))

# Маршрут для создания нового пользователя
@app.route('/admin/users/create', methods=['POST'])
def admin_create_user():
    if 'logged_in' not in session or not session['logged_in'] or session['role'] != 'admin':
        flash('У вас нет доступа к этой странице', 'danger')
        return redirect(url_for('login'))
    
    username = request.form.get('username')
    password = request.form.get('password')
    role = request.form.get('role')
    first_name = request.form.get('first_name', '')
    last_name = request.form.get('last_name', '')
    middle_name = request.form.get('middle_name', '')
    email = request.form.get('email', '')
    group_id = request.form.get('group_id', '') if role == 'student' else ''
    
    # Проверка наличия обязательных полей
    if not username or not password or not role:
        flash('Не все обязательные поля заполнены', 'danger')
        return redirect(url_for('admin_users'))
    
    # Проверка уникальности имени пользователя
    if username in users_db:
        flash(f'Пользователь с логином {username} уже существует', 'danger')
        return redirect(url_for('admin_users'))
    
    # Валидация учетных данных
    is_valid, error_msg = validate_credentials(username, password)
    if not is_valid:
        flash(error_msg, 'danger')
        return redirect(url_for('admin_users'))
    
    # Создание пользователя
    salt = generate_salt()
    password_hash = hash_password(password, salt)
    
    users_db[username] = {
        "salt": salt,
        "password_hash": password_hash,
        "password": password,  # Сохраняем пароль в открытом виде для отображения
        "role": role,
        "failed_attempts": 0,
        "lockout_until": None,
        "first_name": first_name,
        "last_name": last_name,
        "middle_name": middle_name,
        "name": f"{first_name} {last_name}",
        "email": email,
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "last_login": None
    }
    
    # Если это студент и указана группа, добавляем его в группу
    if role == 'student' and group_id and group_id in groups_db:
        if username not in groups_db[group_id]['students']:
            groups_db[group_id]['students'].append(username)
    
    flash(f'Пользователь {username} успешно создан', 'success')
    return redirect(url_for('admin_users'))

# Маршрут для создания новой группы
@app.route('/admin/groups/create', methods=['POST'])
def admin_create_group():
    if 'logged_in' not in session or not session['logged_in'] or session['role'] != 'admin':
        flash('У вас нет доступа к этой странице', 'danger')
        return redirect(url_for('login'))
    
    group_name = request.form.get('group_name')
    group_description = request.form.get('group_description', '')
    
    if not group_name:
        flash('Название группы не может быть пустым', 'danger')
        return redirect(url_for('admin_groups'))
    
    # Проверяем, существует ли группа с таким же названием
    for existing_group in groups_db.values():
        if existing_group['name'].lower() == group_name.lower():
            flash(f'Группа с названием "{group_name}" уже существует', 'danger')
            return redirect(url_for('admin_groups'))
    
    # Генерируем уникальный ID для группы
    group_id = f"group{len(groups_db) + 1}"
    
    # Создаем новую группу
    groups_db[group_id] = {
        "name": group_name,
        "description": group_description,
        "students": []
    }
    
    flash(f'Группа "{group_name}" успешно создана', 'success')
    return redirect(url_for('admin_groups'))

# Маршрут для удаления группы
@app.route('/admin/groups/delete/<group_id>', methods=['POST'])
def admin_delete_group(group_id):
    if 'logged_in' not in session or not session['logged_in'] or session['role'] != 'admin':
        flash('У вас нет доступа к этой странице', 'danger')
        return redirect(url_for('login'))
    
    if group_id in groups_db:
        group_name = groups_db[group_id]['name']
        
        # Удаляем назначения тестов для этой группы
        for test_id, test_info in tests_db.items():
            if isinstance(test_info['assigned_to'], list):
                # Старый формат: список идентификаторов групп
                if group_id in test_info['assigned_to']:
                    test_info['assigned_to'].remove(group_id)
            else:
                # Новый формат: словарь с ключами 'groups' и 'students'
                if group_id in test_info['assigned_to'].get('groups', []):
                    test_info['assigned_to']['groups'].remove(group_id)
        
        # Удаляем группу
        del groups_db[group_id]
        flash(f'Группа "{group_name}" успешно удалена', 'success')
    else:
        flash('Группа не найдена', 'danger')
    
    return redirect(url_for('admin_groups'))

# Маршрут для управления участниками группы
@app.route('/admin/groups/members/<group_id>', methods=['POST'])
def admin_update_group_members(group_id):
    if 'logged_in' not in session or not session['logged_in'] or session['role'] != 'admin':
        flash('У вас нет доступа к этой странице', 'danger')
        return redirect(url_for('login'))
    
    if group_id not in groups_db:
        flash('Группа не найдена', 'danger')
        return redirect(url_for('admin_groups'))
    
    # Получаем список всех студентов, которые отмечены для включения в группу
    student_usernames = request.form.getlist('students')
    
    # Обновляем список студентов в группе
    groups_db[group_id]['students'] = student_usernames
    
    flash(f'Состав группы "{groups_db[group_id]["name"]}" успешно обновлен', 'success')
    return redirect(url_for('admin_groups'))

# Обработчик для редактирования пользователя
@app.route('/admin/users/edit/<username>', methods=['POST'])
def admin_edit_user(username):
    if 'logged_in' not in session or not session['logged_in'] or session['role'] != 'admin':
        flash('У вас нет доступа к этой странице', 'danger')
        return redirect(url_for('login'))
    
    if username not in users_db:
        flash('Пользователь не найден', 'danger')
        return redirect(url_for('admin_users'))
    
    # Получаем данные из формы
    email = request.form.get('email', '')
    new_password = request.form.get('new_password', '')
    role = request.form.get('role', users_db[username]['role'])
    first_name = request.form.get('first_name', '')
    last_name = request.form.get('last_name', '')
    middle_name = request.form.get('middle_name', '')
    group_id = request.form.get('group_id', '')
    
    # Обновляем данные пользователя
    users_db[username]['email'] = email
    users_db[username]['first_name'] = first_name
    users_db[username]['last_name'] = last_name
    users_db[username]['middle_name'] = middle_name
    users_db[username]['role'] = role
    users_db[username]['name'] = f"{first_name} {last_name}"
    
    # Если указан новый пароль, обновляем его
    if new_password:
        # Проверка сложности пароля
        is_valid, error_msg = validate_credentials(username, new_password, False)
        if not is_valid:
            flash(error_msg, 'danger')
            return redirect(url_for('admin_users'))
            
        salt = generate_salt()
        password_hash = hash_password(new_password, salt)
        users_db[username]['salt'] = salt
        users_db[username]['password_hash'] = password_hash
        users_db[username]['password'] = new_password  # Сохраняем пароль в открытом виде
    
    # Обновляем членство в группах, если роль студент
    if role == 'student':
        # Удаляем пользователя из всех групп
        for gid, group in groups_db.items():
            if username in group['students']:
                group['students'].remove(username)
        
        # Добавляем в выбранную группу, если указана
        if group_id and group_id in groups_db:
            if username not in groups_db[group_id]['students']:
                groups_db[group_id]['students'].append(username)
    else:
        # Если роль не студент, удаляем из всех групп
        for gid, group in groups_db.items():
            if username in group['students']:
                group['students'].remove(username)
    
    flash(f'Пользователь {username} успешно обновлен', 'success')
    return redirect(url_for('admin_users'))

# Обработчик для удаления пользователя
@app.route('/admin/users/delete/<username>', methods=['POST'])
def admin_delete_user(username):
    if 'logged_in' not in session or not session['logged_in'] or session['role'] != 'admin':
        flash('У вас нет доступа к этой странице', 'danger')
        return redirect(url_for('login'))
    
    if username not in users_db:
        flash('Пользователь не найден', 'danger')
        return redirect(url_for('admin_users'))
    
    # Удаляем пользователя из всех групп
    for group_id, group in groups_db.items():
        if username in group['students']:
            group['students'].remove(username)
    
    # Удаляем пользователя из базы
    del users_db[username]
    
    flash(f'Пользователь {username} успешно удален', 'success')
    return redirect(url_for('admin_users'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
