from flask import Flask, render_template, redirect, url_for, request, session, flash, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField
from wtforms.validators import DataRequired
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import os, csv
from datetime import datetime

# --- Flask Setup ---
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'

# --- Ensure instance folder exists ---
basedir = os.path.abspath(os.path.dirname(__file__))
db_path = os.path.join(basedir, 'app.db')
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{db_path}"
db = SQLAlchemy(app)

# --- Upload settings ---
UPLOAD_FOLDER = os.path.join(basedir, 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'csv'}  # <-- must be defined BEFORE allowed_file()

# --- Models ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # Admin/Instructor/Student

class Student(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.String(20), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    subject = db.Column(db.String(50))
    grade = db.Column(db.String(10))
    remarks = db.Column(db.String(200))

class Log(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user = db.Column(db.String(100))
    action = db.Column(db.String(255))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# --- Utility Functions ---
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def add_log(user, action):
    log_entry = Log(user=user, action=action)
    db.session.add(log_entry)
    db.session.commit()

# --- Forms ---
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class CreateUserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    role = SelectField('Role', choices=[('Instructor','Instructor'), ('Student','Student')], validators=[DataRequired()])
    submit = SubmitField('Create User')

class StudentForm(FlaskForm):
    student_id = StringField('Student ID', validators=[DataRequired()])
    name = StringField('Name', validators=[DataRequired()])
    subject = StringField('Subject')
    grade = StringField('Grade')
    remarks = StringField('Remarks')
    submit = SubmitField('Save')

class ChangePasswordForm(FlaskForm):
    current_password = PasswordField('Current Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm New Password', validators=[DataRequired()])
    submit = SubmitField('Change Password')

# --- Login Required Decorator ---
def login_required(role=None):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                flash("Please log in first.", "danger")
                return redirect(url_for('login'))
            if role and session.get('role') not in (role if isinstance(role, list) else [role]):
                flash("Access denied.", "danger")
                return redirect(url_for('login'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# --- Routes ---

# Login
@app.route('/', methods=['GET','POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            flash(f'Logged in successfully as {user.username}', 'success')
            add_log(user.username, 'Logged in')
            if user.role == 'Admin':
                return redirect(url_for('dashboard_admin'))
            elif user.role == 'Instructor':
                return redirect(url_for('dashboard_instructor'))
            else:
                return redirect(url_for('dashboard_student'))
        else:
            flash('Invalid username or password', 'danger')
    return render_template('login.html', form=form)

# Logout
@app.route('/logout')
def logout():
    user = session.get('username')
    session.clear()
    if user:
        add_log(user, 'Logged out')
    return redirect(url_for('login'))

# Change Password
@app.route('/change_password', methods=['GET', 'POST'])
@login_required()
def change_password():
    user = User.query.get(session['user_id'])
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if not check_password_hash(user.password, form.current_password.data):
            flash("❌ Current password is incorrect.", "danger")
            return redirect(url_for('change_password'))
        if form.new_password.data != form.confirm_password.data:
            flash("⚠️ New passwords do not match.", "warning")
            return redirect(url_for('change_password'))

        user.password = generate_password_hash(form.new_password.data)
        db.session.commit()
        add_log(user.username, 'Changed password')
        flash("✅ Password changed successfully!", "success")

        if user.role == 'Admin':
            return redirect(url_for('dashboard_admin'))
        elif user.role == 'Instructor':
            return redirect(url_for('dashboard_instructor'))
        else:
            return redirect(url_for('dashboard_student'))

    return render_template('change_password.html', form=form)

# Admin Dashboard
@app.route('/dashboard/admin')
@login_required(role='Admin')
def dashboard_admin():
    students = Student.query.all()
    instructors = User.query.filter_by(role='Instructor').all()
    logs = Log.query.order_by(Log.timestamp.desc()).all()
    return render_template('dashboard_admin.html', students=students, instructors=instructors, logs=logs)

# Instructor Dashboard
@app.route('/dashboard/instructor')
@login_required(role='Instructor')
def dashboard_instructor():
    return render_template('dashboard_instructor.html')

# Student Dashboard
@app.route('/dashboard/student')
@login_required(role='Student')
def dashboard_student():
    student_username = session.get('username')
    students = Student.query.filter_by(student_id=student_username).all()
    student_name = students[0].name if students else student_username
    return render_template('dashboard_student.html', students=students, student_name=student_name)

# Download app.db (Admin only)
@app.route('/dashboard/admin/download_db')
@login_required(role='Admin')
def download_db():
    if not os.path.exists(db_path):
        flash("❌ Database file not found!", "danger")
        return redirect(url_for('dashboard_admin'))
    flash("⬇️ Database download started.", "success")
    return send_file(db_path, as_attachment=True)

# View Logs (Admin)
@app.route('/view_logs')
@login_required(role='Admin')
def view_logs():
    logs = Log.query.order_by(Log.timestamp.desc()).all()
    logs_with_student_name = []
    for log in logs:
        student = Student.query.filter_by(student_id=log.user).first()
        student_name = student.name if student else None
        logs_with_student_name.append({
            'id': log.id,
            'student_name': student_name,
            'user': log.user,
            'action': log.action,
            'timestamp': log.timestamp
        })
    return render_template('logs.html', logs=logs_with_student_name)

# Bulk Delete Logs (Admin)
@app.route('/logs/bulk_delete', methods=['POST'])
@login_required(role='Admin')
def bulk_delete_logs():
    log_ids = request.form.getlist('log_ids')
    if log_ids:
        deleted_logs = []
        for lid in log_ids:
            log = Log.query.get(int(lid))
            if log:
                deleted_logs.append(f"{log.user} - {log.action}")
                db.session.delete(log)
        db.session.commit()
        add_log(session['username'], f'Bulk deleted logs: {", ".join(deleted_logs)}')
        flash(f'{len(log_ids)} log(s) deleted successfully!', 'success')
    else:
        flash('No logs selected for deletion.', 'warning')
    return redirect(url_for('view_logs'))

# Create User (Admin)
@app.route('/dashboard/admin/create_user', methods=['GET','POST'])
@login_required(role='Admin')
def create_user():
    form = CreateUserForm()
    if form.validate_on_submit():
        if User.query.filter_by(username=form.username.data).first():
            flash('Username already exists!', 'danger')
        else:
            hashed_password = generate_password_hash(form.password.data)
            db.session.add(User(username=form.username.data, password=hashed_password, role=form.role.data))
            db.session.commit()
            add_log(session['username'], f'Created {form.role.data} account: {form.username.data}')
            flash(f'{form.role.data} account created successfully!', 'success')
            return redirect(url_for('dashboard_admin'))
    return render_template('create_user.html', form=form)

# View Instructors (Admin)
@app.route('/dashboard/admin/instructors')
@login_required(role='Admin')
def view_instructors():
    instructors = User.query.filter_by(role='Instructor').all()
    return render_template('instructors.html', instructors=instructors)

# Add/Edit/Delete Instructors
@app.route('/dashboard/admin/instructors/add', methods=['GET','POST'])
@login_required(role='Admin')
def add_instructor():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if User.query.filter_by(username=username).first():
            flash('Username already exists!', 'danger')
            return redirect(url_for('add_instructor'))
        hashed_password = generate_password_hash(password)
        db.session.add(User(username=username, password=hashed_password, role='Instructor'))
        db.session.commit()
        add_log(session['username'], f'Added Instructor: {username}')
        flash('Instructor added successfully!', 'success')
        return redirect(url_for('view_instructors'))
    return render_template('add_instructor.html')

@app.route('/dashboard/admin/instructors/edit/<int:id>', methods=['GET','POST'])
@login_required(role='Admin')
def edit_instructor(id):
    instructor = User.query.get_or_404(id)
    if request.method == 'POST':
        old_username = instructor.username
        instructor.username = request.form['username']
        if request.form['password']:
            instructor.password = generate_password_hash(request.form['password'])
        db.session.commit()
        add_log(session['username'], f'Edited Instructor: {old_username} -> {instructor.username}')
        flash('Instructor updated successfully!', 'success')
        return redirect(url_for('view_instructors'))
    return render_template('edit_instructor.html', instructor=instructor)

@app.route('/dashboard/admin/instructors/delete/<int:id>', methods=['POST'])
@login_required(role='Admin')
def delete_instructor(id):
    instructor = User.query.get_or_404(id)
    db.session.delete(instructor)
    db.session.commit()
    add_log(session['username'], f'Deleted Instructor: {instructor.username}')
    flash('Instructor deleted successfully!', 'success')
    return redirect(url_for('view_instructors'))

@app.route('/dashboard/admin/instructors/bulk_delete', methods=['POST'])
@login_required(role='Admin')
def bulk_delete_instructors():
    instructor_ids = request.form.getlist('instructor_ids')
    if instructor_ids:
        deleted_usernames = []
        for iid in instructor_ids:
            instructor = User.query.get(int(iid))
            if instructor and instructor.role == 'Instructor':
                deleted_usernames.append(instructor.username)
                db.session.delete(instructor)
        db.session.commit()
        add_log(session['username'], f'Bulk deleted Instructors: {", ".join(deleted_usernames)}')
        flash(f'{len(instructor_ids)} instructor(s) deleted successfully!', 'success')
    else:
        flash('No instructors selected for deletion.', 'warning')
    return redirect(url_for('view_instructors'))

# View/Add/Edit/Delete Students
@app.route('/dashboard/admin/students')
@app.route('/dashboard/instructor/students')
@login_required(role=['Admin','Instructor'])
def view_students():
    students = Student.query.all()
    return render_template('students.html', students=students)

@app.route('/dashboard/admin/students/add', methods=['GET','POST'])
@app.route('/dashboard/instructor/students/add', methods=['GET','POST'])
@login_required(role=['Admin','Instructor'])
def add_student():
    form = StudentForm()
    if form.validate_on_submit():
        if Student.query.filter_by(student_id=form.student_id.data, subject=form.subject.data).first():
            flash('This student for the same subject already exists!', 'danger')
        else:
            new_student = Student(
                student_id=form.student_id.data,
                name=form.name.data,
                subject=form.subject.data,
                grade=form.grade.data,
                remarks=form.remarks.data
            )
            db.session.add(new_student)
            if not User.query.filter_by(username=form.student_id.data).first():
                hashed_password = generate_password_hash(form.student_id.data)
                db.session.add(User(username=form.student_id.data, password=hashed_password, role='Student'))
            db.session.commit()
            add_log(session['username'], f'Added Student: {form.student_id.data} ({form.subject.data})')
            flash('Student added successfully!', 'success')
            return redirect(url_for('view_students'))
    return render_template('add_student.html', form=form)

@app.route('/dashboard/admin/students/edit/<int:student_id>', methods=['GET','POST'])
@app.route('/dashboard/instructor/students/edit/<int:student_id>', methods=['GET','POST'])
@login_required(role=['Admin','Instructor'])
def edit_student(student_id):
    student = Student.query.get_or_404(student_id)
    form = StudentForm(obj=student)
    if form.validate_on_submit():
        old_data = f'{student.student_id} ({student.subject})'
        student.student_id = form.student_id.data
        student.name = form.name.data
        student.subject = form.subject.data
        student.grade = form.grade.data
        student.remarks = form.remarks.data
        db.session.commit()
        add_log(session['username'], f'Edited Student: {old_data} -> {student.student_id} ({student.subject})')
        flash('Student record updated successfully!', 'success')
        return redirect(url_for('view_students'))
    return render_template('edit_student.html', form=form, student=student)

@app.route('/dashboard/admin/students/delete/<int:student_id>', methods=['POST'])
@app.route('/dashboard/instructor/students/delete/<int:student_id>', methods=['POST'])
@login_required(role=['Admin','Instructor'])
def delete_student(student_id):
    student = Student.query.get_or_404(student_id)
    db.session.delete(student)
    db.session.commit()
    add_log(session['username'], f'Deleted Student: {student.student_id} ({student.subject})')
    flash('Student deleted successfully!', 'success')
    return redirect(url_for('view_students'))

@app.route('/dashboard/admin/students/bulk_delete', methods=['POST'])
@app.route('/dashboard/instructor/students/bulk_delete', methods=['POST'])
@login_required(role=['Admin','Instructor'])
def bulk_delete_students():
    student_ids = request.form.getlist('student_ids')
    if student_ids:
        deleted_students = []
        for sid in student_ids:
            student = Student.query.get(int(sid))
            if student:
                deleted_students.append(f'{student.student_id} ({student.subject})')
                db.session.delete(student)
        db.session.commit()
        add_log(session['username'], f'Bulk deleted Students: {", ".join(deleted_students)}')
        flash(f'{len(student_ids)} student(s) deleted successfully!', 'success')
    else:
        flash('No students selected for deletion.', 'warning')
    return redirect(url_for('view_students'))

# --- CSV upload ---
@app.route('/dashboard/admin/students/upload', methods=['GET','POST'])
@app.route('/dashboard/instructor/students/upload', methods=['GET','POST'])
@login_required(role=['Admin','Instructor'])
def upload_students():
    summary = None

    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part', 'danger')
            return redirect(request.url)
        
        file = request.files['file']
        if file.filename == '':
            flash('No selected file', 'danger')
            return redirect(request.url)
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)

            added_students = []
            skipped_students = []

            with open(filepath, newline='', encoding='utf-8') as csvfile:
                reader = csv.DictReader(csvfile)

                # Validate required columns
                required_columns = ['student_id', 'name', 'subject']
                if not all(col in reader.fieldnames for col in required_columns):
                    flash(f'CSV missing required columns: {required_columns}', 'danger')
                    return redirect(request.url)

                for i, row in enumerate(reader, start=2):  # start=2 to account for header
                    student_id = row['student_id'].strip()
                    name = row['name'].strip()
                    subject = row['subject'].strip()
                    grade = row.get('grade', '').strip()
                    remarks = row.get('remarks', '').strip()

                    student_exists = Student.query.filter_by(
                        student_id=student_id,
                        name=name,
                        subject=subject
                    ).first()

                    if not student_exists:
                        db.session.add(Student(
                            student_id=student_id,
                            name=name,
                            subject=subject,
                            grade=grade,
                            remarks=remarks
                        ))
                        added_students.append(f"{student_id} ({name}) - {subject}")
                    else:
                        skipped_students.append(f"Row {i}: {student_id} ({name}) - {subject}")

                    # Add student as a User if not exists
                    if not User.query.filter_by(username=student_id).first():
                        hashed_password = generate_password_hash(student_id)
                        db.session.add(User(
                            username=student_id,
                            password=hashed_password,
                            role='Student'
                        ))

            try:
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                flash(f"Error saving data: {e}", 'danger')
                return redirect(request.url)

            add_log(session['username'], f'Uploaded CSV: {filename} ({len(added_students)} added, {len(skipped_students)} skipped)')
            flash(f'CSV uploaded: {len(added_students)} added, {len(skipped_students)} skipped duplicates', 'success')

            summary = {
                'added': added_students,
                'skipped': skipped_students
            }

            # Optional: remove uploaded file
            # os.remove(filepath)

            return render_template('upload_students.html', summary=summary)
        else:
            flash('Invalid file type. Only CSV allowed.', 'danger')
            return redirect(request.url)

    return render_template('upload_students.html', summary=summary)

# --- Initialize Database ---
if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create tables if they don't exist

        # Default users
        if not User.query.filter_by(username='admin').first():
            db.session.add(User(username='admin', password=generate_password_hash('admin123'), role='Admin'))
        if not User.query.filter_by(username='instructor').first():
            db.session.add(User(username='instructor', password=generate_password_hash('instr123'), role='Instructor'))
        if not User.query.filter_by(username='student').first():
            db.session.add(User(username='student', password=generate_password_hash('stud123'), role='Student'))

        db.session.commit()

    ENV = os.environ.get('FLASK_ENV', 'development')
    if ENV == 'development':
        app.run(debug=True)
    else:
        from waitress import serve
        serve(app, host='0.0.0.0', port=5000)
