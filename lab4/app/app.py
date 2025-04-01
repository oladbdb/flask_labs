from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from validators import validate_user_form

app = Flask(__name__)
app.secret_key = 'secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Инициализация Flask-Login и БД
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
db = SQLAlchemy(app)

class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(255))

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(128), nullable=False)
    last_name = db.Column(db.String(100))
    first_name = db.Column(db.String(100), nullable=False)
    patronymic = db.Column(db.String(100))
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    role = db.relationship('Role')

    def check_password(self, password):
        return check_password_hash(self.password, password)
    
# Загрузка пользователя по id
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def index():
    users = User.query.all()
    return render_template('index.html', users=users)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        remember_me = 'remember' in request.form 
        
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            login_user(user, remember=remember_me)
            flash('Успешный вход!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Неверный логин или пароль', 'danger')

    return render_template('login.html', title='Авторизация')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Вы успешно вышли из системы.', 'info') 
    return redirect(url_for('index'))

@app.before_request
def init_users():
    db.create_all()
    if not User.query.first():
        default_user = User(
            username='user', 
            password=generate_password_hash('qwerty'),
            first_name='Имя',
            last_name='Фамилия',
            patronymic='Отчество'
            )
        db.session.add(default_user)
        db.session.commit()

    if not Role.query.first():
        admin = Role(
            name='Admin', 
            description='Роль администратора'
        )
        default_role = Role(
            name='Default',
            description='Роль обычного пользователя'
        )
        db.session.add(admin)
        db.session.add(default_role)
        db.session.commit()

@app.route('/user/<int:user_id>')
def view_user(user_id):
    user = User.query.get_or_404(user_id)
    return render_template('view_user.html', user=user)

@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    roles = Role.query.all()

    if request.method == 'POST':
        form_data = request.form.to_dict()
        form_data['role_id'] = request.form.get('role_id') or ''

        errors = validate_user_form(form_data, check_password=False)
        
        if errors:
            return render_template('user_form.html', title='Редактирование пользователя', form_action=url_for('edit_user', user_id=user.id), roles=roles, data=form_data, hide_login_password=True, field_errors=errors)

        user.first_name = form_data['first_name']
        user.last_name = form_data['last_name'] or None
        user.patronymic = form_data['patronymic'] or None
        user.role_id = int(form_data['role_id']) if form_data['role_id'] else None

        try:
            db.session.commit()
            flash("Данные пользователя обновлены", "success")
            return redirect(url_for('index'))
        except:
            db.session.rollback()
            flash("Ошибка при обновлении", "danger")

    data = {
        'last_name': user.last_name,
        'first_name': user.first_name,
        'patronymic': user.patronymic,
        'role_id': str(user.role_id) if user.role_id else ''
    }

    return render_template('user_form.html', title='Редактирование пользователя', form_action='edit_user', roles=roles, data=data, hide_login_password=True, field_errors={})

@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)

    try:
        db.session.delete(user)
        db.session.commit()
        flash(f"Пользователь {user.last_name or ''} {user.first_name} удалён", "success")
    except:
        db.session.rollback()
        flash("Ошибка при удалении пользователя", "danger")

    return redirect(url_for('index'))


@app.route('/create_user', methods=['GET', 'POST'])
@login_required
def create_user():
    roles = Role.query.all()

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        last_name = request.form.get('last_name') or None
        first_name = request.form.get('first_name')
        patronymic = request.form.get('patronymic') or None
        role_id = request.form.get('role_id') or None

        errors = validate_user_form(request.form, check_password=True)

        if errors:
            return render_template('user_form.html', title='Создание пользователя', form_action='create_user', roles=roles, data=request.form, field_errors=errors)

        new_user = User(
            username=username,
            password=generate_password_hash(password),
            last_name=last_name,
            first_name=first_name,
            patronymic=patronymic,
            role_id=int(role_id) if role_id else None
        )
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Пользователь успешно создан!', 'success')
            return redirect(url_for('index'))
        except Exception as e:
            db.session.rollback()
            flash('Ошибка при сохранении в базу данных.', 'danger')
            return render_template('user_form.html', title='Создание пользователя', form_action='create_user', roles=roles, data=request.form, field_errors={})

    return render_template('user_form.html', title='Создание пользователя', form_action='create_user', roles=roles, data={}, field_errors={})


@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    field_errors = {}

    if request.method == 'POST':
        old_password = request.form.get('old_password', '')
        new_password = request.form.get('new_password', '')
        repeat_password = request.form.get('repeat_password', '')

        if not current_user.check_password(old_password):
            field_errors['old_password'] = "Старый пароль введён неверно."

        password_errors = validate_user_form({'password': new_password}, check_password=True)
        if 'password' in password_errors:
            field_errors['new_password'] = password_errors['password']

        if new_password != repeat_password:
            field_errors['repeat_password'] = "Пароли не совпадают."

        if field_errors:
            return render_template('change_password.html', field_errors=field_errors, data=request.form)


        current_user.password = generate_password_hash(new_password)
        db.session.commit()
        flash("Пароль успешно изменён", "success")
        return redirect(url_for('index'))

    return render_template('change_password.html', field_errors={}, data={})

if __name__ == '__main__':
    app.run(debug=True)
