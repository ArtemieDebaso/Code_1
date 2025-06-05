# СУБД-Лаб - Система управления тестированием

Продвинутая система аутентификации и управления тестами на Python с комплексными функциями безопасности пользователей и оценки знаний.

## Ключевые возможности

- **Система ролей**: Администратор, преподаватель, студент
- **Безопасная аутентификация**: SHA-256 хеширование паролей
- **Управление тестами**: Создание, редактирование, назначение тестов
- **Предотвращение повторного прохождения**: Блокировка повторных попыток
- **Визуальные индикаторы**: Статус пройденных тестов
- **Система оценок**: 5-балльная шкала (2-5)
- **Результаты в реальном времени**: Немедленное отображение результатов

## Технологии

- **Backend**: Python 3.9+, Flask
- **Frontend**: Bootstrap 5, HTML5, JavaScript
- **Аутентификация**: Пользовательские алгоритмы хеширования
- **Визуализация**: Chart.js для аналитики

## Требования для запуска

### Системные требования
- Python 3.9 или выше
- PostgreSQL 12+ (опционально, для сохранения данных)
- Git (для клонирования)

### Python зависимости
```
flask>=2.3.0
flask-sqlalchemy>=3.0.0
gunicorn>=21.0.0
psycopg2-binary>=2.9.0
email-validator>=2.0.0
```

## Установка и запуск

### 1. Скачивание и распаковка
```bash
# Скачайте архив test_system_project.tar.gz
# Распакуйте архив
tar -xzf test_system_project.tar.gz
cd test_system_project
```

### 2. Установка зависимостей
```bash
# Создайте виртуальное окружение (рекомендуется)
python -m venv venv

# Активируйте виртуальное окружение
# На Windows:
venv\Scripts\activate
# На Linux/Mac:
source venv/bin/activate

# Установите зависимости
pip install flask flask-sqlalchemy gunicorn psycopg2-binary email-validator
```

### 3. Настройка переменных окружения
```bash
# Установите переменные окружения
export SESSION_SECRET="your_secret_key_here"
export DATABASE_URL="sqlite:///test_system.db"  # или PostgreSQL URL
```

На Windows используйте:
```cmd
set SESSION_SECRET=your_secret_key_here
set DATABASE_URL=sqlite:///test_system.db
```

### 4. Запуск приложения

#### Режим разработки:
```bash
python main.py
```

#### Продакшн режим:
```bash
gunicorn --bind 0.0.0.0:5000 --reuse-port --reload main:app
```

### 5. Доступ к приложению
Откройте браузер и перейдите по адресу: `http://localhost:5000`

## Тестовые аккаунты

- **Администратор**: `admin` / `Password123`
- **Преподаватель**: `teacher` / `Teacher123`
- **Студент**: `student` / `Student123`

## Сохранение данных после перезагрузки

### Проблема с текущей версией
**Важно**: В текущей версии все данные хранятся в памяти (словари Python), поэтому при перезапуске сервера все изменения теряются.

### Решения для постоянного хранения данных:

#### 1. PostgreSQL (Рекомендуемое решение)
```bash
# Установите PostgreSQL
# Ubuntu/Debian:
sudo apt install postgresql postgresql-contrib

# Создайте базу данных
sudo -u postgres createdb test_system

# Установите переменную окружения
export DATABASE_URL="postgresql://username:password@localhost/test_system"
```

#### 2. SQLite (Простое решение)
```bash
# Используйте SQLite для локального хранения
export DATABASE_URL="sqlite:///test_system.db"
```

#### 3. Модификация кода для использования базы данных
Для использования реальной базы данных нужно:

1. Создать модели SQLAlchemy
2. Заменить словари на запросы к БД
3. Добавить миграции

### Быстрое решение для сохранения данных
Добавьте в `main.py` автосохранение в JSON файлы:

```python
import json
import os

# Функция сохранения данных
def save_data():
    data = {
        'users_db': users_db,
        'tests_db': tests_db,
        'groups_db': groups_db,
        'test_results_db': test_results_db
    }
    with open('app_data.json', 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

# Функция загрузки данных
def load_data():
    global users_db, tests_db, groups_db, test_results_db
    if os.path.exists('app_data.json'):
        with open('app_data.json', 'r', encoding='utf-8') as f:
            data = json.load(f)
            users_db.update(data.get('users_db', {}))
            tests_db.update(data.get('tests_db', {}))
            groups_db.update(data.get('groups_db', {}))
            test_results_db.update(data.get('test_results_db', {}))

# Вызывайте save_data() после каждого изменения данных
```

## Файловая структура

```
test_system_project/
├── main.py                 # Основной файл приложения
├── pyproject.toml         # Конфигурация проекта
├── README.md              # Данный файл
├── templates/             # HTML шаблоны
│   ├── layout.html        # Базовый шаблон
│   ├── index.html         # Главная страница
│   ├── login.html         # Страница входа
│   ├── admin/             # Шаблоны администратора
│   ├── teacher/           # Шаблоны преподавателя
│   └── student/           # Шаблоны студента
└── attached_assets/       # Прикрепленные файлы
```

## Безопасность

- Измените `SESSION_SECRET` на случайную строку в продакшене
- Используйте HTTPS в продакшене
- Настройте файрволл для ограничения доступа
- Регулярно обновляйте зависимости

## Поддержка

Для вопросов и поддержки обращайтесь к разработчику.

## Лицензия

Проект создан в образовательных целях.