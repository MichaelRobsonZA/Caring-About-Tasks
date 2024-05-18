from flask import Flask, render_template, redirect, url_for, flash, request, jsonify, abort
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField, SelectMultipleField
from wtforms.validators import DataRequired, Length
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timezone
from wtforms.fields import DateField
from flask_socketio import SocketIO


app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'

db = SQLAlchemy(app)
migrate = Migrate(app, db)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

socketio = SocketIO(app)

current_time = datetime.now(timezone.utc)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    type = db.Column(db.String(20), nullable=False)
    tasks_given = db.relationship('Task', foreign_keys='Task.taskgiver_id', backref='taskgiver', lazy=True)
    tasks_accepted = db.relationship('Task', foreign_keys='Task.taskacceptor_id', backref='taskacceptor', lazy=True)
    online = db.Column(db.Boolean, default=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    # SocketIO Events
@socketio.on('connect')
def handle_connect():
    current_user.online = True
    db.session.commit()
    broadcast_online_users()

@socketio.on('disconnect')
def handle_disconnect():
    current_user.online = False
    db.session.commit()
    broadcast_online_users()

def broadcast_online_users():
    online_users = User.query.filter_by(online=True).all()
    online_usernames = [user.username for user in online_users]
    socketio.emit('online_users', {'usernames': online_usernames}, broadcast=True)

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), nullable=False, default='initiated')
    deadline = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    taskgiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    taskacceptor_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    def __repr__(self):
        return f'Task {self.title}'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=1)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=1)])
    submit = SubmitField('Log In')

class SignupForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=1)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=1)])
    role = SelectField('Role', choices=[('taskgiver', 'Task Giver'), ('taskacceptor', 'Task Acceptor')])
    submit = SubmitField('Sign Up')

class TaskForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    description = StringField('Description', validators=[DataRequired()])
    deadline = DateField('Deadline', validators=[DataRequired()])
    submit = SubmitField('Create Task')

class AssignmentForm(FlaskForm):
    username = SelectMultipleField('Assign To', coerce=int)
    submit = SubmitField('Assign Task')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            flash('Logged in successfully!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'error')
    return render_template('login.html', form=form)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, type=form.role.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Account created successfully!', 'success')
        return redirect(url_for('login'))
    return render_template('signup.html', form=form)

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.type == 'taskgiver':
        tasks = Task.query.filter_by(taskgiver_id=current_user.id).all()
        return render_template('dashboard_taskgiver.html', tasks=tasks)
    else:
        tasks = Task.query.filter_by(taskacceptor_id=current_user.id).all()
        return render_template('dashboard_taskacceptor.html', tasks=tasks)

@app.route('/online_users')
@login_required
def online_users():
    online_users = User.query.filter_by(online=True).all()
    return render_template('online_users.html', online_users=online_users)
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('login'))

@app.route('/create_task', methods=['GET', 'POST'])
@login_required
def create_task():
    if current_user.type != 'taskgiver':
        flash('Only task givers can create tasks', 'error')
        return redirect(url_for('dashboard'))
    form = TaskForm()
    if form.validate_on_submit():
        task = Task(title=form.title.data, description=form.description.data, taskgiver=current_user)
        db.session.add(task)
        db.session.commit()
        flash('Task created successfully!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('create_task.html', form=form)

@app.route('/task_details/<int:task_id>')
@login_required
def task_details(task_id):
    task = Task.query.get(task_id)
    if task is None:
        flash('Task not found.', 'error')
        return redirect(url_for('dashboard'))
    
    taskacceptor_users = []
    if task.taskacceptor_id:
        taskacceptor_user = User.query.get(task.taskacceptor_id)
        taskacceptor_users.append(taskacceptor_user)
    
    return render_template('task_details.html', task=task, taskacceptor_users=taskacceptor_users)

@app.route('/online_taskacceptors')
@login_required
def online_taskacceptors():
    online_users = User.query.filter_by(type='taskacceptor', online=True).all()
    online_usernames = [user.username for user in online_users]
    return jsonify(online_usernames)

@app.route('/assign_task/<int:task_id>', methods=['GET', 'POST'])
@login_required
def assign_task(task_id):
    if current_user.type != 'taskgiver':
        flash('Only task givers can assign tasks', 'error')
        return redirect(url_for('dashboard'))

    task = Task.query.get(task_id)
    if task is None:
        flash('Task not found.', 'error')
        return redirect(url_for('dashboard'))

    form = AssignmentForm()
    form.username.choices = [(user.id, user.username) for user in User.query.filter_by(type='taskacceptor').all()]

    if form.validate_on_submit():
        for user_id in form.username.data:
            user = User.query.get(user_id)
            task.taskacceptor = user
            db.session.commit()
        flash('Task assigned successfully!', 'success')
        return redirect(url_for('dashboard'))

    users = User.query.filter_by(type='taskacceptor').all()  # Fetch users for the dropdown
    return render_template('assign_task.html', form=form, task=task, users=users)


@app.route('/accept_task/<int:task_id>', methods=['POST'])
@login_required
def accept_task(task_id):
    if current_user.type != 'taskacceptor':
        flash('Only task acceptors can accept tasks', 'error')
        return redirect(url_for('dashboard'))

    task = Task.query.get(task_id)
    if task is None:
        flash('Task not found.', 'error')
        return redirect(url_for('dashboard'))

    if task.status != 'initiated':
        flash('Task cannot be accepted as it is not in initiated status.', 'error')
        return redirect(url_for('dashboard'))

    task.taskacceptor = current_user
    task.status = 'assigned'
    db.session.commit()
    flash('Task accepted successfully!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/complete_task/<int:task_id>', methods=['POST'])
@login_required
def complete_task(task_id):
    if current_user.type != 'taskacceptor':
        flash('Only task acceptors can complete tasks', 'error')
        return redirect(url_for('dashboard'))

    task = Task.query.get(task_id)
    if task is None:
        flash('Task not found.', 'error')
        return redirect(url_for('dashboard'))

    if task.status != 'assigned':
        flash('Task cannot be completed as it is not assigned.', 'error')
        return redirect(url_for('dashboard'))

    task.status = 'completed'
    db.session.commit()
    flash('Task completed successfully!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/view_task/<int:task_id>')
@login_required
def view_task(task_id):
    task = Task.query.get(task_id)
    if task is None:
        flash('Task not found.', 'error')
        return redirect(url_for('dashboard'))
    return render_template('view_task.html', task=task)

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

if __name__ == '__main__':
    socketio.run(app, debug=True)
