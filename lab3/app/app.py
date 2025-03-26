from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask import session
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'secret_key'
application = app


# Инициализация Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)

login_manager.login_view = "login"


users = {}

class User(UserMixin):
    def __init__(self, id, username, password):
        self.id = id
        self.username = username
        self.password = password

    def check_password(self, password):
        return check_password_hash(self.password, password)
    
# Загрузка пользователя по id
@login_manager.user_loader
def load_user(user_id):
    return users.get(user_id)


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/counter')
def counter():
    if 'visit_count' not in session:
        session['visit_count'] = 0
    session['visit_count'] += 1

    return render_template('counter.html', title='Счётчик посещений', count=session['visit_count'])

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        remember_me = 'remember' in request.form 
        
        user = next((user for user in users.values() if user.username == username), None)

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

@app.before_first_request
def init_users():
    if not users:
        users['1'] = User(id='1', username='user', password=generate_password_hash('qwerty'))

@app.route('/secret')
@login_required
def secret():
    return render_template('secret.html', title='Секретная страница')



if __name__ == '__main__':
    app.run(debug=True)
