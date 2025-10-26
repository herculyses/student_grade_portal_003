from flask import Flask, render_template, redirect, url_for, request, session, flash, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import IntegerField, TextAreaField, StringField, PasswordField, FileField, SubmitField, SelectField
from wtforms.validators import DataRequired, Optional
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import os, csv
from datetime import datetime
import time
from flask import get_flashed_messages
import csv
from flask import Response

# --- Flask Setup ---
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'

# --- Ensure instance folder exists ---
basedir = os.path.abspath(os.path.dirname(__file__))
db_path = os.path.join(basedir, 'app.db')
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{db_path}"
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {"connect_args": {"timeout": 15}}
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
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
    __tablename__ = 'student'
    student_id = db.Column(db.String(100), primary_key=True)
    subject = db.Column(db.String(100), primary_key=True)
    name = db.Column(db.String(150), nullable=False)

    # Quizzes
    quiz1 = db.Column(db.String(10), default='0')
    quiz2 = db.Column(db.String(10), default='0')
    quiz3 = db.Column(db.String(10), default='0')
    quiz4 = db.Column(db.String(10), default='0')
    quiz5 = db.Column(db.String(10), default='0')
    quiz6 = db.Column(db.String(10), default='0')
    quiz7 = db.Column(db.String(10), default='0')
    quiz8 = db.Column(db.String(10), default='0')

    # Exams
    midterm_exam = db.Column(db.String(10), default='0')
    finals_exam = db.Column(db.String(10), default='0')

    # Grades and remarks (separated)
    midterm_grade = db.Column(db.String(10), default='0')
    finals_grade = db.Column(db.String(10), default='0')
    midterm_remarks = db.Column(db.String(50))
    finals_remarks = db.Column(db.String(50))

    # Overall grade and remarks
    overall_grade = db.Column(db.String(10), default='0')
    overall_remarks = db.Column(db.String(50))

    __table_args__ = (
        db.UniqueConstraint('student_id', 'subject', name='uix_student_subject'),
    )

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
    subject = StringField('Subject', validators=[Optional()])
    
    # Quizzes 1-8
    quiz1 = StringField('Quiz 1', validators=[Optional()])
    quiz2 = StringField('Quiz 2', validators=[Optional()])
    quiz3 = StringField('Quiz 3', validators=[Optional()])
    quiz4 = StringField('Quiz 4', validators=[Optional()])
    quiz5 = StringField('Quiz 5', validators=[Optional()])
    quiz6 = StringField('Quiz 6', validators=[Optional()])
    quiz7 = StringField('Quiz 7', validators=[Optional()])
    quiz8 = StringField('Quiz 8', validators=[Optional()])

    # Exams and grades
    midterm_exam = StringField('Midterm Exam', validators=[Optional()])
    finals_exam = StringField('Final Exam', validators=[Optional()])
    midterm_grade = StringField('Midterm Grade', validators=[Optional()])
    finals_grade = StringField('Final Grade', validators=[Optional()])

    # Midterm & Finals remarks
    midterm_remarks = StringField('Midterm Remarks', validators=[Optional()])
    finals_remarks = StringField('Finals Remarks', validators=[Optional()])

    # Overall grade & remarks
    overall_grade = StringField('Overall Grade', validators=[Optional()])
    overall_remarks = StringField('Overall Remarks', validators=[Optional()])

    submit = SubmitField('Save Changes')

class ChangePasswordForm(FlaskForm):
    current_password = PasswordField('Current Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm New Password', validators=[DataRequired()])
    submit = SubmitField('Change Password')

class UploadCSVForm(FlaskForm):
    file = FileField('CSV File', validators=[DataRequired()])
    submit = SubmitField('Upload')

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
@app.route('/', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            # ✅ Store integer primary key in session
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            flash(f'Logged in successfully as {user.username}', 'success')
            add_log(user.username, 'Logged in')
            time.sleep(1)  # Let DB/session settle

            # Redirect based on role
            if user.role == 'Admin':
                return redirect(url_for('dashboard_admin'))
            elif user.role == 'Instructor':
                return redirect(url_for('dashboard_instructor'))
            else:  # Student
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
        time.sleep(1)  # 🕒 Prevent SQLite lock or empty data
    return redirect(url_for('login'))

# Change Password
@app.route('/change_password', methods=['GET', 'POST'])
@login_required()
def change_password():
    user = User.query.get(session['user_id'])

    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        # Validate current password
        if not check_password_hash(user.password, current_password):
            flash("❌ Current password is incorrect.", "danger")
            return redirect(url_for('change_password'))

        # Ensure new password matches confirmation
        if new_password != confirm_password:
            flash("⚠️ New passwords do not match.", "warning")
            return redirect(url_for('change_password'))

        # Ensure new password isn't same as current
        if check_password_hash(user.password, new_password):
            flash("⚠️ New password must be different from the current one.", "warning")
            return redirect(url_for('change_password'))

        # Update password securely
        user.password = generate_password_hash(new_password)
        db.session.commit()

        # Log the event
        add_log(
            user.username,
            f"Changed their password (Role: {user.role})"
        )
        time.sleep(1)

        # Force logout for security
        session.clear()
        flash("✅ Nautro na imuhang password! Pwede na ta manlupad.", "success")
        return redirect(url_for('login'))

    return render_template('change_password.html')

# --- Dashboards ---
# ---- Admin Dashboard ----
@app.route('/dashboard/admin')
@login_required(role='Admin')
def dashboard_admin():
    # Fetch all students
    students = Student.query.all()
    
    # Fetch all instructors
    instructors = User.query.filter_by(role='Instructor').all()
    
    # Fetch all logs (newest first)
    logs = Log.query.order_by(Log.timestamp.desc()).all()
    
    # Render template
    return render_template(
        'dashboard_admin.html',
        students=students,
        instructors=instructors,
        logs=logs
    )

# ---- Instructor Dashboard ----
@app.route('/dashboard/instructor')
@login_required(role='Instructor')
def dashboard_instructor():
    # Fetch all students (or filter by instructor if needed)
    students = Student.query.all()  

    return render_template(
        'dashboard_instructor.html',
        students=students
    )

# ---- Student Dashboard ----
@app.route('/dashboard/student')
@login_required(role=['Student', 'Admin', 'Instructor'])
def dashboard_student():
    username = session.get('username')
    role = session.get('role')

    if role == 'Student':
        # Students only see their own records
        students = Student.query.filter_by(student_id=username).all()
        if not students:
            flash("Student record not found.", "danger")
            return redirect(url_for('login'))
        student_name = students[0].name
    else:
        # Admin/Instructor: show all students
        students = Student.query.all()
        student_name = None

    return render_template(
        'dashboard_student.html',
        students=students,
        student_name=student_name,
        role=role,
        getattr=getattr  # Pass getattr to Jinja2 for dynamic quiz fields
    )

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

# ---- Student Grades ----
@app.route('/student/grades/<student_id>')
@login_required(role=['Admin', 'Instructor', 'Student'])
def student_grades(student_id):
    """
    Fetch all records for a given student I number (student_id).
    Display grades as stored in the database (no computation).
    """
    # Ensure student_id is a string and stripped of extra spaces
    student_id = str(student_id).strip()

    # Fetch all student records that match this student_id (I number)
    students = Student.query.filter_by(student_id=student_id).all()

    if not students:
        flash(f"No records found for student ID {student_id}", "warning")
        # Redirect based on user role
        role = session.get('role')
        if role == 'Student':
            return redirect(url_for('dashboard_student'))
        elif role == 'Instructor':
            return redirect(url_for('dashboard_instructor'))
        else:
            return redirect(url_for('dashboard_admin'))

    # Render template with all subjects for this student
    # No computation; display stored quiz, exam, and overall grades
    return render_template(
        'student_grades.html',
        students=students,
        student_name=students[0].name  # Use first record's name
    )

# ---- Student Performance ----
@app.route('/student/performance/<string:student_id>')
@login_required(role=['Student','Admin','Instructor'])
def student_performance(student_id):
    student_id = student_id.strip()

    # Fetch the first student record for this student_id
    student_obj = Student.query.filter_by(student_id=student_id).first()
    if not student_obj:
        flash("Student record not found.", "danger")
        role = session.get('role')
        if role == 'Admin':
            return redirect(url_for('dashboard_admin'))
        elif role == 'Instructor':
            return redirect(url_for('dashboard_instructor'))
        else:
            return redirect(url_for('dashboard_student'))

    # Students can only view their own records
    if session.get('role') == 'Student' and student_id != session.get('username'):
        flash("Access denied.", "danger")
        return redirect(url_for('dashboard_student'))

    # Fetch all subjects/records for this student
    student_records = Student.query.filter_by(student_id=student_id).all()

    performance = []
    for record in student_records:
        quizzes = [record.quiz1, record.quiz2, record.quiz3, record.quiz4,
                   record.quiz5, record.quiz6, record.quiz7, record.quiz8]
        performance.append({
            "subject": record.subject,
            "quizzes": quizzes,
            "midterm_exam": record.midterm_exam,
            "finals_exam": record.finals_exam,
            "midterm_grade": record.midterm_grade,
            "finals_grade": record.finals_grade,
            "midterm_remarks": record.midterm_remarks,
            "finals_remarks": record.finals_remarks
        })

    return render_template(
        'student_performance.html',
        student=student_obj,
        performance=performance,
        role=session.get('role')
    )

# View/Add/Edit/Delete Students
@app.route('/dashboard/admin/students')
@app.route('/dashboard/instructor/students')
@login_required(role=['Admin','Instructor'])
def view_students():
    students = Student.query.all()
    return render_template('students.html', students=students)

# --- Student add ---
@app.route('/add_student', methods=['GET', 'POST'])
@login_required(role=['Admin','Instructor'])
def add_student():
    form = StudentForm()
    if form.validate_on_submit():
        # No automatic calculation; all fields stored as strings
        student = Student(
            student_id=form.student_id.data,
            name=form.name.data,
            subject=form.subject.data,
            quiz1=form.quiz1.data or '0',
            quiz2=form.quiz2.data or '0',
            quiz3=form.quiz3.data or '0',
            quiz4=form.quiz4.data or '0',
            quiz5=form.quiz5.data or '0',
            quiz6=form.quiz6.data or '0',
            quiz7=form.quiz7.data or '0',
            quiz8=form.quiz8.data or '0',
            midterm_exam=form.midterm_exam.data or '0',
            finals_exam=form.finals_exam.data or '0',
            midterm_grade=form.midterm_grade.data or '0',
            finals_grade=form.finals_grade.data or '0',
            overall_grade=form.overall_grade.data or '0',
            overall_remarks=form.overall_remarks.data or ''
        )
        db.session.add(student)
        db.session.commit()
        flash(f"Student {student.name} added successfully!", "success")
        return redirect(url_for('view_students'))

    return render_template('add_student.html', form=form)

# --- Student Edit ---
@app.route('/dashboard/admin/students/edit/<student_id>/<subject>', methods=['GET', 'POST'])
@app.route('/dashboard/instructor/students/edit/<student_id>/<subject>', methods=['GET', 'POST'])
@login_required(role=['Admin', 'Instructor'])
def edit_student(student_id, subject):
    student = Student.query.get_or_404((student_id, subject))
    form = StudentForm(obj=student)

    if form.validate_on_submit():
        old_student_id = student.student_id
        new_student_id = form.student_id.data.strip()
        new_subject = form.subject.data.strip() or student.subject

        # Update core info
        student.student_id = new_student_id
        student.name = form.name.data.strip()
        student.subject = new_subject

        # Update quizzes
        for i in range(1, 9):
            setattr(student, f'quiz{i}', getattr(form, f'quiz{i}').data or '')

        # Update exams and grades (all strings)
        student.midterm_exam = form.midterm_exam.data or ''
        student.finals_exam = form.finals_exam.data or ''
        student.midterm_grade = form.midterm_grade.data or ''
        student.finals_grade = form.finals_grade.data or ''
        student.overall_grade = form.overall_grade.data or ''
        student.midterm_remarks = form.midterm_remarks.data or ''
        student.finals_remarks = form.finals_remarks.data or ''
        student.overall_remarks = form.overall_remarks.data or ''

        # Update User table if student_id changed
        if old_student_id != new_student_id:
            existing_user = User.query.filter_by(username=new_student_id).first()
            if existing_user:
                flash(f"A user with ID {new_student_id} already exists!", "danger")
                return render_template('edit_student.html', form=form, student=student)

            user = User.query.filter_by(username=old_student_id, role='Student').first()
            if user:
                user.username = new_student_id

            db.session.flush()

        db.session.commit()
        add_log(session.get('username'),
                f'Edited Student: {old_student_id} → {student.student_id} ({new_subject})')
        flash('Student record updated successfully!', 'success')

        return redirect(url_for('dashboard_admin') if session.get('role') == 'Admin'
                            else url_for('dashboard_instructor'))

    # Only pre-fill manually on GET
    if request.method == 'GET':
        for i in range(1, 9):
            getattr(form, f'quiz{i}').data = getattr(student, f'quiz{i}', '') or ''
        form.midterm_exam.data = student.midterm_exam or ''
        form.finals_exam.data = student.finals_exam or ''
        form.midterm_grade.data = student.midterm_grade or ''
        form.finals_grade.data = student.finals_grade or ''
        form.overall_grade.data = student.overall_grade or ''
        form.midterm_remarks.data = student.midterm_remarks or ''
        form.finals_remarks.data = student.finals_remarks or ''
        form.overall_remarks.data = student.overall_remarks or ''

    return render_template('edit_student.html', form=form, student=student)

# --- Student delete ---
@app.route('/dashboard/admin/students/delete/<int:student_id>', methods=['POST'])
@app.route('/dashboard/instructor/students/delete/<int:student_id>', methods=['POST'])
@login_required(role=['Admin','Instructor'])
def delete_student(student_id):
    student = Student.query.get_or_404(student_id)
    
    # Delete corresponding User if exists
    user = User.query.filter_by(username=student.student_id, role='Student').first()
    if user:
        db.session.delete(user)

    db.session.delete(student)
    db.session.commit()

    add_log(session['username'], f'Deleted Student: {student.student_id} ({student.subject})')
    flash('Student deleted successfully!', 'success')
    return redirect(url_for('view_students'))

# --- Student bulk delete ---
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

                # Delete corresponding User
                user = User.query.filter_by(username=student.student_id, role='Student').first()
                if user:
                    db.session.delete(user)

                db.session.delete(student)

        db.session.commit()
        add_log(session['username'], f'Bulk deleted Students: {", ".join(deleted_students)}')
        flash(f'{len(student_ids)} student(s) deleted successfully!', 'success')
    else:
        flash('No students selected for deletion.', 'warning')
    return redirect(url_for('view_students'))

# --- CSV upload ---
@app.route('/dashboard/admin/students/upload', methods=['GET', 'POST'])
@app.route('/dashboard/instructor/students/upload', methods=['GET', 'POST'])
@login_required(role=['Admin', 'Instructor'])
def upload_students():
    form = UploadCSVForm()
    summary = None
    errors = []

    def safe_str(value):
        return str(value).strip() if value is not None else ""

    username = session.get('username', 'UnknownUser')

    if form.validate_on_submit():
        file = form.file.data
        if not file or file.filename == '':
            msg = "No file selected."
            errors.append(msg)
            add_log(username, f"CSV upload failed: {msg}")
            return render_template('upload_students.html', form=form, summary=summary, errors=errors)

        filename = secure_filename(file.filename)
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        added_students = []
        updated_students = []
        skipped_students = []

        try:
            with open(filepath, newline='', encoding='latin-1') as csvfile:
                reader = csv.DictReader(csvfile)
                required_columns = ['student_id', 'name', 'subject']
                if not reader.fieldnames or not all(col in reader.fieldnames for col in required_columns):
                    msg = f"CSV missing required columns: {required_columns}"
                    errors.append(msg)
                    add_log(username, f"CSV upload failed ({filename}): {msg}")
                    return render_template('upload_students.html', form=form, summary=summary, errors=errors)

                for row_num, row in enumerate(reader, start=2):
                    try:
                        student_id = safe_str(row.get('student_id'))
                        name = safe_str(row.get('name'))
                        subject = safe_str(row.get('subject'))

                        if not student_id or not name or not subject:
                            msg = f"Row {row_num}: missing required field(s)."
                            errors.append(msg)
                            add_log(username, f"CSV upload warning ({filename}): {msg}")
                            continue

                        # Prepare grade-related fields
                        field_updates = {
                            'midterm_grade': safe_str(row.get('midterm_grade')),
                            'finals_grade': safe_str(row.get('finals_grade')),
                            'midterm_remarks': safe_str(row.get('midterm_remarks')),
                            'finals_remarks': safe_str(row.get('finals_remarks')),
                            'midterm_exam': safe_str(row.get('midterm_exam')),
                            'finals_exam': safe_str(row.get('finals_exam')),
                            'overall_grade': safe_str(row.get('overall_grade')),
                            'overall_remarks': safe_str(row.get('overall_remarks')),
                        }
                        for j in range(1, 9):
                            field_updates[f'quiz{j}'] = safe_str(row.get(f'quiz{j}'))

                        # --- Lookup student by student_id and subject ---
                        student = Student.query.filter_by(student_id=student_id, subject=subject).first()
                        if student:
                            # Update existing record
                            for key, value in field_updates.items():
                                if hasattr(student, key):
                                    setattr(student, key, value)
                            student.name = name
                            updated_students.append(f"{student_id} - {name} ({subject})")
                        else:
                            # Create new student-subject record
                            create_kwargs = {'student_id': student_id, 'name': name, 'subject': subject}
                            for k, v in field_updates.items():
                                if hasattr(Student, k):
                                    create_kwargs[k] = v
                            new_student = Student(**create_kwargs)
                            db.session.add(new_student)
                            added_students.append(f"{student_id} - {name} ({subject})")

                        # --- Ensure User exists without duplicating ---
                        existing_user = User.query.filter_by(username=student_id).first()
                        if not existing_user:
                            hashed_password = generate_password_hash(student_id)
                            new_user = User(username=student_id, password=hashed_password, role='Student')
                            db.session.add(new_user)
                        else:
                            # Correct role if needed
                            if existing_user.role != 'Student':
                                existing_user.role = 'Student'

                    except Exception as row_error:
                        msg = f"Row {row_num}: {type(row_error).__name__} - {row_error}"
                        errors.append(msg)
                        add_log(username, f"CSV upload error ({filename}): {msg}")

            # Commit once after all rows processed
            try:
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                msg = f"Database commit failed: {type(e).__name__} - {e}"
                errors.append(msg)
                add_log(username, f"CSV upload failed ({filename}): {msg}")

        except Exception as file_error:
            msg = f"Error reading file: {type(file_error).__name__} - {file_error}"
            errors.append(msg)
            add_log(username, f"CSV upload failed ({filename}): {msg}")

        # Render summary including errors
        if errors:
            add_log(username, f"CSV upload completed with {len(errors)} error(s) ({filename}).")
            return render_template('upload_students.html', form=form, summary=None, errors=errors)

        add_log(username, f'Uploaded CSV: {filename} ({len(added_students)} added, {len(updated_students)} updated)')
        flash(f'CSV uploaded: {len(added_students)} added, {len(updated_students)} updated', 'success')

        summary = {
            'added': added_students,
            'updated': updated_students,
            'skipped': skipped_students  # currently empty; can populate for duplicates if needed
        }
        return render_template('upload_students.html', form=form, summary=summary, errors=None)

    return render_template('upload_students.html', form=form, summary=summary, errors=None)

# --- CSV download ---
@app.route('/dashboard/admin/download_csv')
@login_required(role=['Admin', 'Instructor'])
def download_csv():
    students = Student.query.all()

    def clean(value, is_numeric=False):
        """
        Convert None or invalid values to blank (for strings) or 0 (for numeric fields).
        """
        if value is None or value == '#N/A' or (is_numeric and value == ''):
            return 0.0 if is_numeric else ''
        return value

    def generate():
        # Header row — must exactly match your upload format
        yield (
            "student_id,name,subject,"
            "quiz1,quiz2,quiz3,quiz4,quiz5,quiz6,quiz7,quiz8,"
            "midterm_exam,finals_exam,"
            "midterm_grade,midterm_remarks,"
            "finals_grade,finals_remarks,"
            "overall_grade,overall_remarks\n"
        )

        for s in students:
            quizzes = [clean(getattr(s, f'quiz{i}', 0), is_numeric=True) for i in range(1, 9)]
            row = [
                clean(s.student_id),
                clean(s.name),
                clean(s.subject),
                *quizzes,
                clean(s.midterm_exam, is_numeric=True),
                clean(s.finals_exam, is_numeric=True),
                clean(s.midterm_grade, is_numeric=True),
                clean(s.midterm_remarks),
                clean(s.finals_grade, is_numeric=True),
                clean(s.finals_remarks),
                clean(s.overall_grade, is_numeric=True),
                clean(s.overall_remarks)
            ]
            yield ",".join(map(str, row)) + "\n"

    return Response(
        generate(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=students.csv"},
        content_type='text/csv; charset=latin-1'
    )

# --- Initialize Database ---
if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create tables if they don't exist

        # Default users
        if not User.query.filter_by(username='admin').first():
            db.session.add(User(username='admin', password=generate_password_hash('fangnailed'), role='Admin'))
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
