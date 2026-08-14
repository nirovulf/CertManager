from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

def make_aware(dt):
    """Делает datetime осознанным (с timezone), если он наивный"""
    if dt is None:
        return None
    if dt.tzinfo is not None:
        return dt
    return dt.replace(tzinfo=timezone.utc)

import base64
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///certificates.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'

db = SQLAlchemy(app)

# Добавляем timezone в контекст шаблонов
@app.context_processor
def inject_timezone():
    from datetime import timezone
    return dict(timezone=timezone)

# Создаем папку для загрузок
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# === МОДЕЛИ ДАННЫХ ===

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def __repr__(self):
        return f'<User {self.username}>'


class Organization(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), unique=True, nullable=False)
    inn = db.Column(db.String(12))
    kpp = db.Column(db.String(9))
    ogrn = db.Column(db.String(13))
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    def __repr__(self):
        return f'<Organization {self.name}>'


class Department(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    organization_id = db.Column(db.Integer, db.ForeignKey('organization.id'), nullable=False)
    organization = db.relationship('Organization', backref=db.backref('departments', lazy=True))
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    def __repr__(self):
        return f'<Department {self.name}>'


class Position(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    def __repr__(self):
        return f'<Position {self.name}>'


class Employee(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    last_name = db.Column(db.String(100), nullable=False)
    first_name = db.Column(db.String(100), nullable=False)
    middle_name = db.Column(db.String(100))
    snils = db.Column(db.String(11))
    inn = db.Column(db.String(12))
    position_id = db.Column(db.Integer, db.ForeignKey('position.id'))
    department_id = db.Column(db.Integer, db.ForeignKey('department.id'))
    position = db.relationship('Position', backref=db.backref('employees', lazy=True))
    department = db.relationship('Department', backref=db.backref('employees', lazy=True))
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    
    @property
    def full_name(self):
        return f"{self.last_name} {self.first_name} {self.middle_name or ''}".strip()
    
    def __repr__(self):
        return f'<Employee {self.full_name}>'


class TokenType(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)  # Например: Рутокен, JaCarta, eToken
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    def __repr__(self):
        return f'<TokenType {self.name}>'


class Token(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    serial_number = db.Column(db.String(100), unique=True, nullable=False)
    token_type_id = db.Column(db.Integer, db.ForeignKey('token_type.id'), nullable=False)
    token_type = db.relationship('TokenType', backref=db.backref('tokens', lazy=True))
    label = db.Column(db.String(200))
    employee_id = db.Column(db.Integer, db.ForeignKey('employee.id'))
    employee = db.relationship('Employee', backref=db.backref('tokens', lazy=True))
    issued_at = db.Column(db.Date)
    returned_at = db.Column(db.Date)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    def __repr__(self):
        return f'<Token {self.serial_number}>'


class Certificate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    subject = db.Column(db.Text, nullable=False)
    issuer = db.Column(db.Text, nullable=False)
    serial_number = db.Column(db.String(100), nullable=False)
    not_before = db.Column(db.DateTime, nullable=False)
    not_after = db.Column(db.DateTime, nullable=False)
    thumbprint = db.Column(db.String(64), unique=True, nullable=False)
    certificate_data = db.Column(db.Text, nullable=False)
    employee_id = db.Column(db.Integer, db.ForeignKey('employee.id'), nullable=False)
    token_id = db.Column(db.Integer, db.ForeignKey('token.id'))
    employee = db.relationship('Employee', backref=db.backref('certificates', lazy=True))
    token = db.relationship('Token', backref=db.backref('certificates', lazy=True))
    imported_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    is_valid = db.Column(db.Boolean, default=True)
    
    def __repr__(self):
        return f'<Certificate {self.thumbprint[:16]}...>'
    
    @property
    def days_until_expiry(self):
        not_after = make_aware(self.not_after) if self.not_after else None
        if not_after is None:
            return 0
        delta = not_after - datetime.now(timezone.utc)
        return delta.days
    
    @property
    def is_expired(self):
        not_after = make_aware(self.not_after) if self.not_after else None
        if not_after is None:
            return False
        return datetime.now(timezone.utc) > not_after
    
    @property
    def status(self):
        if self.is_expired:
            return 'Истёк'
        days = self.days_until_expiry
        if days <= 30:
            return 'Скоро истекает'
        elif days <= 90:
            return 'Требует внимания'
        return 'Действует'


# === ФУНКЦИИ ПАРСИНГА СЕРТИФИКАТОВ ===

def parse_certificate(file_content):
    """Парсит сертификат и извлекает информацию"""
    try:
        # Пробуем как DER
        try:
            cert = x509.load_der_x509_certificate(file_content, default_backend())
        except:
            # Пробуем как PEM
            cert = x509.load_pem_x509_certificate(file_content, default_backend())
        
        # Извлекаем данные из сертификата
        subject_attrs = {}
        for attr in cert.subject:
            oid_name = attr.oid._name
            subject_attrs[oid_name] = attr.value
        
        issuer_attrs = {}
        for attr in cert.issuer:
            oid_name = attr.oid._name
            issuer_attrs[oid_name] = attr.value
        
        # Получаем отпечаток (SHA256)
        thumbprint = base64.b16encode(cert.fingerprint(hashes.SHA256())).decode()
        
        # Пытаемся найти ФИО в сертификате
        full_name = None
        snils = None
        inn = None
        issuer_cn = None
        
        # CN обычно содержит ФИО
        cn = subject_attrs.get('commonName', '')
        if cn:
            full_name = cn
        
        # Извлекаем Issuer CN (например, "Федеральное казначейство")
        issuer_cn = issuer_attrs.get('commonName', '')
        
        # Ищем СНИЛС и ИНН в полях сертификата
        for attr in cert.subject:
            value = attr.value
            # СНИЛС обычно 11 цифр
            if len(value) == 11 and value.isdigit():
                snils = value
            # ИНН 10 или 12 цифр
            elif len(value) in [10, 12] and value.isdigit() and not snils:
                inn = value
        
        return {
            'subject': str(cert.subject),
            'issuer': issuer_cn if issuer_cn else str(cert.issuer),
            'serial_number': str(cert.serial_number),
            'not_before': cert.not_valid_before_utc if hasattr(cert, 'not_valid_before_utc') else make_aware(cert.not_valid_before),
            'not_after': cert.not_valid_after_utc if hasattr(cert, 'not_valid_after_utc') else make_aware(cert.not_valid_after),
            'thumbprint': thumbprint,
            'certificate_data': base64.b64encode(file_content).decode(),
            'parsed_name': full_name,
            'parsed_snils': snils,
            'parsed_inn': inn
        }
    except Exception as e:
        raise ValueError(f"Ошибка парсинга сертификата: {str(e)}")


def find_or_create_employee(parsed_data):
    """Находит или создаёт сотрудника на основе данных из сертификата"""
    # Сначала ищем по СНИЛС
    if parsed_data.get('parsed_snils'):
        employee = Employee.query.filter_by(snils=parsed_data['parsed_snils']).first()
        if employee:
            return employee
    
    # Затем по ИНН
    if parsed_data.get('parsed_inn'):
        employee = Employee.query.filter_by(inn=parsed_data['parsed_inn']).first()
        if employee:
            return employee
    
    # Пытаемся распарсить ФИО
    full_name = parsed_data.get('parsed_name', '')
    if full_name:
        parts = full_name.split()
        if len(parts) >= 2:
            last_name = parts[0]
            first_name = parts[1]
            middle_name = parts[2] if len(parts) > 2 else ''
            
            # Ищем по фамилии и имени
            employee = Employee.query.filter_by(
                last_name=last_name,
                first_name=first_name
            ).first()
            if employee:
                return employee
            
            # Если не нашли, создаём нового
            employee = Employee(
                last_name=last_name,
                first_name=first_name,
                middle_name=middle_name,
                snils=parsed_data.get('parsed_snils'),
                inn=parsed_data.get('parsed_inn')
            )
            db.session.add(employee)
            db.session.commit()
            return employee
    
    return None


# === ДЕКОРАТОР АВТОРИЗАЦИИ ===

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Пожалуйста, войдите в систему', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


# === МАРШРУТЫ ===

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['is_admin'] = user.is_admin
            flash('Вы успешно вошли в систему', 'success')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))
        else:
            flash('Неверное имя пользователя или пароль', 'error')
    
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('Вы вышли из системы', 'info')
    return redirect(url_for('login'))


@app.route('/users')
@login_required
def users_list():
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template('users.html', users=users)


@app.route('/user/add', methods=['GET', 'POST'])
@login_required
def add_user():
    if not session.get('is_admin'):
        flash('Доступ запрещён. Только администраторы могут создавать пользователей.', 'error')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        is_admin = request.form.get('is_admin') == 'on'
        
        if not username or not password:
            flash('Имя пользователя и пароль обязательны', 'error')
            return redirect(request.url)
        
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Пользователь с таким именем уже существует', 'error')
            return redirect(request.url)
        
        user = User(username=username, is_admin=is_admin)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
        flash(f'Пользователь {username} успешно создан', 'success')
        return redirect(url_for('users_list'))
    
    return render_template('user_form.html', user=None)


@app.route('/user/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if not session.get('is_admin'):
        flash('Доступ запрещён. Только администраторы могут редактировать пользователей.', 'error')
        return redirect(url_for('index'))
    
    user = User.query.get_or_404(user_id)
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        is_admin = request.form.get('is_admin') == 'on'
        
        if username != user.username:
            existing_user = User.query.filter_by(username=username).first()
            if existing_user:
                flash('Пользователь с таким именем уже существует', 'error')
                return redirect(request.url)
            user.username = username
        
        user.is_admin = is_admin
        
        if password:
            user.set_password(password)
        
        db.session.commit()
        flash('Данные пользователя обновлены', 'success')
        return redirect(url_for('users_list'))
    
    return render_template('user_form.html', user=user)


@app.route('/user/<int:user_id>/delete', methods=['POST'])
@login_required
def delete_user(user_id):
    if not session.get('is_admin'):
        flash('Доступ запрещён. Только администраторы могут удалять пользователей.', 'error')
        return redirect(url_for('index'))
    
    user = User.query.get_or_404(user_id)
    
    # Нельзя удалить самого себя
    if user.id == session.get('user_id'):
        flash('Нельзя удалить свою собственную учётную запись', 'error')
        return redirect(url_for('users_list'))
    
    db.session.delete(user)
    db.session.commit()
    flash('Пользователь удалён', 'success')
    return redirect(url_for('users_list'))


@app.route('/')
@login_required
def index():
    certificates = Certificate.query.order_by(Certificate.imported_at.desc()).all()
    return render_template('index.html', certificates=certificates)


@app.route('/certificates')
@login_required
def certificates_list():
    certificates = Certificate.query.order_by(Certificate.not_after.asc()).all()
    return render_template('certificates.html', certificates=certificates)


@app.route('/import', methods=['GET', 'POST'])
@login_required
def import_certificate():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('Файл не выбран', 'error')
            return redirect(request.url)
        
        file = request.files['file']
        if file.filename == '':
            flash('Файл не выбран', 'error')
            return redirect(request.url)
        
        if file:
            try:
                file_content = file.read()
                cert_data = parse_certificate(file_content)
                
                # Проверяем, нет ли уже такого сертификата
                existing_cert = Certificate.query.filter_by(thumbprint=cert_data['thumbprint']).first()
                if existing_cert:
                    flash('Такой сертификат уже загружен', 'warning')
                    return redirect(url_for('certificates_list'))
                
                # Находим или создаём сотрудника
                employee = find_or_create_employee(cert_data)
                
                if not employee:
                    flash('Не удалось автоматически определить владельца сертификата. Создайте сотрудника вручную.', 'warning')
                    return render_template('manual_employee.html', cert_data=cert_data)
                
                # Создаём запись о сертификате
                certificate = Certificate(
                    subject=cert_data['subject'],
                    issuer=cert_data['issuer'],
                    serial_number=cert_data['serial_number'],
                    not_before=cert_data['not_before'],
                    not_after=cert_data['not_after'],
                    thumbprint=cert_data['thumbprint'],
                    certificate_data=cert_data['certificate_data'],
                    employee_id=employee.id
                )
                db.session.add(certificate)
                db.session.commit()
                
                flash(f'Сертификат успешно импортирован для сотрудника {employee.full_name}', 'success')
                return redirect(url_for('certificate_detail', cert_id=certificate.id))
                
            except ValueError as e:
                flash(str(e), 'error')
            except Exception as e:
                flash(f'Ошибка при импорте: {str(e)}', 'error')
        
        return redirect(request.url)
    
    return render_template('import.html')


@app.route('/certificate/<int:cert_id>')
@login_required
def certificate_detail(cert_id):
    certificate = Certificate.query.get_or_404(cert_id)
    return render_template('certificate_detail.html', certificate=certificate)


@app.route('/employees')
@login_required
def employees_list():
    employees = Employee.query.order_by(Employee.last_name.asc()).all()
    return render_template('employees.html', employees=employees)


@app.route('/employee/add', methods=['GET', 'POST'])
@login_required
def add_employee():
    if request.method == 'POST':
        employee = Employee(
            last_name=request.form['last_name'],
            first_name=request.form['first_name'],
            middle_name=request.form.get('middle_name', ''),
            snils=request.form.get('snils', ''),
            inn=request.form.get('inn', ''),
            position_id=request.form.get('position_id') or None,
            department_id=request.form.get('department_id') or None
        )
        db.session.add(employee)
        db.session.commit()
        flash('Сотрудник успешно добавлен', 'success')
        return redirect(url_for('employees_list'))
    
    positions = Position.query.all()
    departments = Department.query.all()
    return render_template('employee_form.html', employee=None, positions=positions, departments=departments)


@app.route('/employee/<int:emp_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_employee(emp_id):
    employee = Employee.query.get_or_404(emp_id)
    if request.method == 'POST':
        employee.last_name = request.form['last_name']
        employee.first_name = request.form['first_name']
        employee.middle_name = request.form.get('middle_name', '')
        employee.snils = request.form.get('snils', '')
        employee.inn = request.form.get('inn', '')
        employee.position_id = request.form.get('position_id') or None
        employee.department_id = request.form.get('department_id') or None
        db.session.commit()
        flash('Данные сотрудника обновлены', 'success')
        return redirect(url_for('employees_list'))
    
    positions = Position.query.all()
    departments = Department.query.all()
    return render_template('employee_form.html', employee=employee, positions=positions, departments=departments)


@app.route('/organizations')
@login_required
def organizations_list():
    organizations = Organization.query.all()
    return render_template('organizations.html', organizations=organizations)


@app.route('/organization/<int:org_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_organization(org_id):
    org = Organization.query.get_or_404(org_id)
    if request.method == 'POST':
        org.name = request.form['name']
        org.inn = request.form.get('inn', '')
        org.kpp = request.form.get('kpp', '')
        org.ogrn = request.form.get('ogrn', '')
        db.session.commit()
        flash('Данные организации обновлены', 'success')
        return redirect(url_for('organizations_list'))
    return render_template('organization_form.html', organization=org)


@app.route('/organization/add', methods=['GET', 'POST'])
@login_required
def add_organization():
    if request.method == 'POST':
        org = Organization(
            name=request.form['name'],
            inn=request.form.get('inn', ''),
            kpp=request.form.get('kpp', ''),
            ogrn=request.form.get('ogrn', '')
        )
        db.session.add(org)
        db.session.commit()
        flash('Организация успешно добавлена', 'success')
        return redirect(url_for('organizations_list'))
    return render_template('organization_form.html', organization=None)


@app.route('/department/<int:dept_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_department(dept_id):
    dept = Department.query.get_or_404(dept_id)
    if request.method == 'POST':
        dept.name = request.form['name']
        dept.organization_id = request.form['organization_id']
        db.session.commit()
        flash('Данные подразделения обновлены', 'success')
        return redirect(url_for('departments_list'))
    organizations = Organization.query.all()
    return render_template('department_form.html', department=dept, organizations=organizations)


@app.route('/department/add', methods=['GET', 'POST'])
@login_required
def add_department():
    if request.method == 'POST':
        dept = Department(
            name=request.form['name'],
            organization_id=request.form['organization_id']
        )
        db.session.add(dept)
        db.session.commit()
        flash('Подразделение успешно добавлено', 'success')
        return redirect(url_for('departments_list'))
    organizations = Organization.query.all()
    return render_template('department_form.html', department=None, organizations=organizations)


@app.route('/departments')
@login_required
def departments_list():
    departments = Department.query.all()
    return render_template('departments.html', departments=departments)


@app.route('/positions')
@login_required
def positions_list():
    positions = Position.query.all()
    return render_template('positions.html', positions=positions)


@app.route('/position/<int:pos_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_position(pos_id):
    position = Position.query.get_or_404(pos_id)
    if request.method == 'POST':
        position.name = request.form['name']
        db.session.commit()
        flash('Данные должности обновлены', 'success')
        return redirect(url_for('positions_list'))
    return render_template('position_form.html', position=position)


@app.route('/position/add', methods=['GET', 'POST'])
@login_required
def add_position():
    if request.method == 'POST':
        position = Position(name=request.form['name'])
        db.session.add(position)
        db.session.commit()
        flash('Должность успешно добавлена', 'success')
        return redirect(url_for('positions_list'))
    return render_template('position_form.html', position=None)


@app.route('/tokens')
@login_required
def tokens_list():
    tokens = Token.query.all()
    return render_template('tokens.html', tokens=tokens)


@app.route('/token/<int:token_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_token(token_id):
    token = Token.query.get_or_404(token_id)
    if request.method == 'POST':
        token.serial_number = request.form['serial_number']
        token.token_type_id = request.form['token_type_id']
        token.label = request.form.get('label', '')
        token.employee_id = request.form.get('employee_id') or None
        token.is_active = request.form.get('is_active') == 'on'
        db.session.commit()
        flash('Данные носителя обновлены', 'success')
        return redirect(url_for('tokens_list'))
    token_types = TokenType.query.all()
    employees = Employee.query.all()
    return render_template('token_form.html', token=token, token_types=token_types, employees=employees)


@app.route('/token/add', methods=['GET', 'POST'])
@login_required
def add_token():
    if request.method == 'POST':
        token = Token(
            serial_number=request.form['serial_number'],
            token_type_id=request.form['token_type_id'],
            label=request.form.get('label', ''),
            employee_id=request.form.get('employee_id') or None,
            is_active=request.form.get('is_active') == 'on'
        )
        db.session.add(token)
        db.session.commit()
        flash('Носитель успешно добавлен', 'success')
        return redirect(url_for('tokens_list'))
    token_types = TokenType.query.all()
    employees = Employee.query.all()
    return render_template('token_form.html', token=None, token_types=token_types, employees=employees)


@app.route('/token-types')
@login_required
def token_types_list():
    token_types = TokenType.query.all()
    return render_template('token_types.html', token_types=token_types)


@app.route('/token-type/<int:type_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_token_type(type_id):
    token_type = TokenType.query.get_or_404(type_id)
    if request.method == 'POST':
        token_type.name = request.form['name']
        token_type.description = request.form.get('description', '')
        db.session.commit()
        flash('Данные типа носителя обновлены', 'success')
        return redirect(url_for('token_types_list'))
    return render_template('token_type_form.html', token_type=token_type)


@app.route('/token-type/add', methods=['GET', 'POST'])
@login_required
def add_token_type():
    if request.method == 'POST':
        token_type = TokenType(
            name=request.form['name'],
            description=request.form.get('description', '')
        )
        db.session.add(token_type)
        db.session.commit()
        flash('Тип носителя успешно добавлен', 'success')
        return redirect(url_for('token_types_list'))
    return render_template('token_type_form.html', token_type=None)


@app.route('/api/employees/search')
@login_required
def search_employees():
    query = request.args.get('q', '')
    employees = Employee.query.filter(
        (Employee.last_name.ilike(f'%{query}%')) |
        (Employee.first_name.ilike(f'%{query}%')) |
        (Employee.snils.ilike(f'%{query}%')) |
        (Employee.inn.ilike(f'%{query}%'))
    ).limit(10).all()
    
    results = [{
        'id': emp.id,
        'full_name': emp.full_name,
        'snils': emp.snils,
        'inn': emp.inn
    } for emp in employees]
    
    return jsonify(results)


# === МАРШРУТЫ ДЛЯ МАССОВОГО ИМПОРТА СЕРТИФИКАТОВ ===

@app.route('/import-multiple', methods=['GET', 'POST'])
@login_required
def import_multiple_certificates():
    if request.method == 'POST':
        if 'files' not in request.files:
            flash('Файлы не выбраны', 'error')
            return redirect(request.url)
        
        files = request.files.getlist('files')
        if not files or all(f.filename == '' for f in files):
            flash('Файлы не выбраны', 'error')
            return redirect(request.url)
        
        success_count = 0
        error_count = 0
        duplicate_count = 0
        
        for file in files:
            if file.filename == '':
                continue
            
            try:
                file_content = file.read()
                cert_data = parse_certificate(file_content)
                
                # Проверяем, нет ли уже такого сертификата
                existing_cert = Certificate.query.filter_by(thumbprint=cert_data['thumbprint']).first()
                if existing_cert:
                    duplicate_count += 1
                    continue
                
                # Находим или создаём сотрудника
                employee = find_or_create_employee(cert_data)
                
                if not employee:
                    error_count += 1
                    continue
                
                # Создаём запись о сертификате
                certificate = Certificate(
                    subject=cert_data['subject'],
                    issuer=cert_data['issuer'],
                    serial_number=cert_data['serial_number'],
                    not_before=cert_data['not_before'],
                    not_after=cert_data['not_after'],
                    thumbprint=cert_data['thumbprint'],
                    certificate_data=cert_data['certificate_data'],
                    employee_id=employee.id
                )
                db.session.add(certificate)
                success_count += 1
                
            except Exception as e:
                error_count += 1
        
        db.session.commit()
        
        message = f"Импортировано: {success_count}"
        if duplicate_count > 0:
            message += f", дубликатов: {duplicate_count}"
        if error_count > 0:
            message += f", ошибок: {error_count}"
        
        flash(message, 'success')
        return redirect(url_for('certificates_list'))
    
    return render_template('import_multiple.html')


# === ИНИЦИАЛИЗАЦИЯ БД ===

def init_db():
    with app.app_context():
        db.create_all()
        
        # Создаём пользователя администратора по умолчанию если нет пользователей
        if not User.query.first():
            admin = User(username='admin', is_admin=True)
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()
            print("Создан пользователь admin с паролем admin123")
        
        # Добавляем начальные данные если пусто
        if not TokenType.query.first():
            default_types = ['Рутокен', 'JaCarta', 'eToken', 'Токен УЭК', 'Другой']
            for type_name in default_types:
                token_type = TokenType(name=type_name)
                db.session.add(token_type)
            db.session.commit()
        
        if not Position.query.first():
            default_positions = ['Директор', 'Главный бухгалтер', 'Бухгалтер', 'Менеджер', 'Специалист', 'Администратор']
            for pos_name in default_positions:
                position = Position(name=pos_name)
                db.session.add(position)
            db.session.commit()


if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)
