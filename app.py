import os
from datetime import datetime
from flask import Flask, render_template, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField, SelectMultipleField, BooleanField
from wtforms.validators import DataRequired, Length
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms.fields import DateField
from flask_socketio import SocketIO

# Initialize the Flask application
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default-secret-key')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'

# Initialize extensions
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
socketio = SocketIO(app)

# Define models
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

# Define forms
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
    requires_acceptance = BooleanField('Requires Acceptance')
    submit = SubmitField('Create Task')

class AssignmentForm(FlaskForm):
    username = SelectMultipleField('Assign To', coerce=int)
    submit = SubmitField('Assign Task')

# SocketIO Events
@socketio.on('connect')
def handle_connect():
    if current_user.is_authenticated:
        current_user.online = True
        db.session.commit()
        broadcast_online_users()

@socketio.on('disconnect')
def handle_disconnect():
    if current_user.is_authenticated:
        current_user.online = False
        db.session.commit()
        broadcast_online_users()

def broadcast_online_users():
    online_users = User.query.filter_by(online=True).all()
    online_usernames = [user.username for user in online_users]
    socketio.emit('online_users', {'usernames': online_usernames}, broadcast=True)

# Routes
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
        requested_tasks = Task.query.filter_by(status='requested').join(User, Task.taskgiver_id == User.id).filter(User.tasks_given.any(id=Task.id)).all()
        return render_template('dashboard_taskacceptor.html', tasks=tasks, requested_tasks=requested_tasks)

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
        requires_acceptance = form.requires_acceptance.data
        task = Task(
            title=form.title.data,
            description=form.description.data,
            deadline=form.deadline.data,
            taskgiver=current_user,
            status='initiated' if requires_acceptance else 'in progress'
        )
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
        taskacceptor_users.append(User.query.get(task.taskacceptor_id))

    return render_template('task_details.html', task=task, taskacceptor_users=taskacceptor_users)

@app.route('/online_taskacceptors')
@login_required
def online_taskacceptors():
    online_users = User.query.filter_by(type='taskacceptor', online=True).all()
    online_usernames = [user.username for user in online_users]
    return jsonify(online_usernames)

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

    if task.status not in ['initiated', 'requested']:
        flash('Task cannot be accepted as it is not in initiated or requested status.', 'error')
        return redirect(url_for('dashboard'))

    task.taskacceptor = current_user
    task.status = 'in progress'  # Change status to 'in progress'
    db.session.commit()

    # Optional: Notify the task giver about acceptance
    task_giver = User.query.get(task.taskgiver_id)
    if task_giver:
        flash(f'Task "{task.title}" accepted by {current_user.username}', 'success')

    flash('Task accepted successfully!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/request_task/<int:task_id>', methods=['GET', 'POST'])
@login_required
def request_task(task_id):
    if current_user.type != 'taskgiver':
        flash('Only task givers can request tasks', 'error')
        return redirect(url_for('dashboard'))

    task = Task.query.get(task_id)
    if task is None:
        flash('Task not found.', 'error')
        return redirect(url_for('dashboard'))

    if task.status != 'initiated':
        flash('Task cannot be requested as it is not in initiated status.', 'error')
        return redirect(url_for('dashboard'))

    form = AssignmentForm()
    form.username.choices = [(user.id, user.username) for user in User.query.filter_by(type='taskacceptor').all()]
    if form.validate_on_submit():
        for user_id in form.username.data:
            user = User.query.get(user_id)
            # TODOAssuming you want to notify each user or take some action here
            # This part of the logic needs to be implemented as per my requirement

        task.status = 'requested'
        db.session.commit()
        flash('Task requested successfully!', 'success')
        return redirect(url_for('dashboard'))

    users = User.query.filter_by(type='taskacceptor').all()  # Fetch users for the dropdown
    return render_template('request_task.html', form=form, task=task, users=users)

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
            # TODOAssuming I want to notify each user or take some action here
            # This part of the logic needs to be implemented as per my requirement

        task.status = 'assigned'
        db.session.commit()
        flash('Task assigned successfully!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('assign_task.html', form=form, task=task)

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

    if task.status != 'in progress':
        flash('Task cannot be completed as it is not in progress.', 'error')
        return redirect(url_for('dashboard'))

    task.status = 'completed'
    db.session.commit()
    flash('Task completed successfully!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/delete_task/<int:task_id>', methods=['POST'])
@login_required
def delete_task(task_id):
    task = Task.query.get(task_id)
    if task is None:
        flash('Task not found.', 'error')
        return redirect(url_for('dashboard'))

    if current_user.type != 'taskgiver' or task.taskgiver_id != current_user.id:
        flash('Only the task giver who created the task can delete it', 'error')
        return redirect(url_for('dashboard'))

    db.session.delete(task)
    db.session.commit()
    flash('Task deleted successfully!', 'success')
    return redirect(url_for('dashboard'))


# Error handlers
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500



# Run the application
if __name__ == '__main__':
    socketio.run(app, debug=True)