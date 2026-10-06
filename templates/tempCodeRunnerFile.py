from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
from functools import wraps

app = Flask(__name__)
app.secret_key = "guidance_secret_key"

DATABASE = "guidance.db"


# ==========================================================
# DATABASE
# ==========================================================

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def initialize_database():
    conn = get_db()
    cursor = conn.cursor()

    # USERS TABLE
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL
        )
    """)

    # APPOINTMENTS TABLE
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS appointments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id INTEGER NOT NULL,
            date TEXT NOT NULL,
            time TEXT NOT NULL,
            reason TEXT NOT NULL,
            status TEXT DEFAULT 'Pending',
            FOREIGN KEY (student_id) REFERENCES users(id)
        )
    """)

    # Create default users
    cursor.execute("SELECT * FROM users WHERE username = ?", ("student",))
    if cursor.fetchone() is None:
        cursor.execute("""
            INSERT INTO users (name, username, password, role)
            VALUES (?, ?, ?, ?)
        """, ("Juan Student", "student", "1234", "student"))

    cursor.execute("SELECT * FROM users WHERE username = ?", ("counselor",))
    if cursor.fetchone() is None:
        cursor.execute("""
            INSERT INTO users (name, username, password, role)
            VALUES (?, ?, ?, ?)
        """, ("Ms. Maria Counselor", "counselor", "1234", "counselor"))

    cursor.execute("SELECT * FROM users WHERE username = ?", ("admin",))
    if cursor.fetchone() is None:
        cursor.execute("""
            INSERT INTO users (name, username, password, role)
            VALUES (?, ?, ?, ?)
        """, ("System Administrator", "admin", "1234", "admin"))

    conn.commit()
    conn.close()


# ==========================================================
# OOP CLASSES
# ==========================================================

class User:

    def __init__(self, id, name, username, password, role):
        self.id = id
        self.name = name
        self.username = username
        self.password = password
        self.role = role

    @staticmethod
    def login(username, password):

        conn = get_db()

        user = conn.execute("""
            SELECT * FROM users
            WHERE username = ? AND password = ?
        """, (username, password)).fetchone()

        conn.close()

        if user:
            return User(
                user["id"],
                user["name"],
                user["username"],
                user["password"],
                user["role"]
            )

        return None


class Appointment:

    def __init__(self, id, student_id, date, time, reason, status):
        self.id = id
        self.student_id = student_id
        self.date = date
        self.time = time
        self.reason = reason
        self.status = status

    @staticmethod
    def create(student_id, date, time, reason):

        conn = get_db()

        conn.execute("""
            INSERT INTO appointments
            (student_id, date, time, reason, status)
            VALUES (?, ?, ?, ?, ?)
        """, (student_id, date, time, reason, "Pending"))

        conn.commit()
        conn.close()

    @staticmethod
    def get_student_appointments(student_id):

        conn = get_db()

        appointments = conn.execute("""
            SELECT *
            FROM appointments
            WHERE student_id = ?
            ORDER BY date, time
        """, (student_id,)).fetchall()

        conn.close()

        return appointments

    @staticmethod
    def get_all_appointments():

        conn = get_db()

        appointments = conn.execute("""
            SELECT
                appointments.id,
                appointments.date,
                appointments.time,
                appointments.reason,
                appointments.status,
                users.name AS student_name
            FROM appointments
            JOIN users
            ON appointments.student_id = users.id
            ORDER BY appointments.date, appointments.time
        """).fetchall()

        conn.close()

        return appointments

    @staticmethod
    def update_status(appointment_id, status):

        conn = get_db()

        conn.execute("""
            UPDATE appointments
            SET status = ?
            WHERE id = ?
        """, (status, appointment_id))

        conn.commit()
        conn.close()


# ==========================================================
# LOGIN REQUIRED DECORATOR
# ==========================================================

def login_required(function):

    @wraps(function)
    def wrapper(*args, **kwargs):

        if "user_id" not in session:
            flash("Please login first.", "error")
            return redirect(url_for("login"))

        return function(*args, **kwargs)

    return wrapper


def role_required(role):

    def decorator(function):

        @wraps(function)
        def wrapper(*args, **kwargs):

            if "user_id" not in session:
                return redirect(url_for("login"))

            if session.get("role") != role:
                flash("You do not have permission to access this page.", "error")
                return redirect(url_for("dashboard"))

            return function(*args, **kwargs)

        return wrapper

    return decorator


# ==========================================================
# LOGIN
# ==========================================================

@app.route("/", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        user = User.login(username, password)

        if user:

            session["user_id"] = user.id
            session["name"] = user.name
            session["role"] = user.role

            return redirect(url_for("dashboard"))

        flash("Invalid username or password.", "error")

    return render_template("login.html")


# ==========================================================
# DASHBOARD REDIRECT
# ==========================================================

@app.route("/dashboard")
@login_required
def dashboard():

    role = session.get("role")

    if role == "student":
        return redirect(url_for("student_dashboard"))

    elif role == "counselor":
        return redirect(url_for("counselor_dashboard"))

    elif role == "admin":
        return redirect(url_for("admin_dashboard"))

    return redirect(url_for("login"))


# ==========================================================
# STUDENT DASHBOARD
# ==========================================================

@app.route("/student")
@role_required("student")
def student_dashboard():

    appointments = Appointment.get_student_appointments(
        session["user_id"]
    )

    return render_template(
        "student.html",
        appointments=appointments
    )


# ==========================================================
# BOOK APPOINTMENT
# ==========================================================

@app.route("/book", methods=["GET", "POST"])
@role_required("student")
def book_appointment():

    if request.method == "POST":

        date = request.form["date"]
        time = request.form["time"]
        reason = request.form["reason"]

        if not date or not time or not reason:

            flash("Please complete all fields.", "error")

            return redirect(url_for("book_appointment"))

        Appointment.create(
            session["user_id"],
            date,
            time,
            reason
        )

        flash("Appointment request submitted successfully!", "success")

        return redirect(url_for("student_dashboard"))

    return render_template("book.html")


# ==========================================================
# COUNSELOR DASHBOARD
# ==========================================================

@app.route("/counselor")
@role_required("counselor")
def counselor_dashboard():

    appointments = Appointment.get_all_appointments()

    return render_template(
        "counselor.html",
        appointments=appointments
    )


# ==========================================================
# APPROVE APPOINTMENT
# ==========================================================

@app.route("/approve/<int:appointment_id>")
@role_required("counselor")
def approve_appointment(appointment_id):

    Appointment.update_status(
        appointment_id,
        "Approved"
    )

    flash("Appointment approved.", "success")

    return redirect(url_for("counselor_dashboard"))


# ==========================================================
# REJECT APPOINTMENT
# ==========================================================

@app.route("/reject/<int:appointment_id>")
@role_required("counselor")
def reject_appointment(appointment_id):

    Appointment.update_status(
        appointment_id,
        "Rejected"
    )

    flash("Appointment rejected.", "success")

    return redirect(url_for("counselor_dashboard"))


# ==========================================================
# ADMIN DASHBOARD
# ==========================================================

@app.route("/admin")
@role_required("admin")
def admin_dashboard():

    conn = get_db()

    users = conn.execute("""
        SELECT * FROM users
        ORDER BY id DESC
    """).fetchall()

    appointments = conn.execute("""
        SELECT
            appointments.id,
            appointments.date,
            appointments.time,
            appointments.reason,
            appointments.status,
            users.name AS student_name
        FROM appointments
        JOIN users
        ON appointments.student_id = users.id
        ORDER BY appointments.date, appointments.time
    """).fetchall()

    total_users = conn.execute("""
        SELECT COUNT(*) FROM users
    """).fetchone()[0]

    total_appointments = conn.execute("""
        SELECT COUNT(*) FROM appointments
    """).fetchone()[0]

    pending = conn.execute("""
        SELECT COUNT(*)
        FROM appointments
        WHERE status = 'Pending'
    """).fetchone()[0]

    approved = conn.execute("""
        SELECT COUNT(*)
        FROM appointments
        WHERE status = 'Approved'
    """).fetchone()[0]

    conn.close()

    return render_template(
        "admin.html",
        users=users,
        appointments=appointments,
        total_users=total_users,
        total_appointments=total_appointments,
        pending=pending,
        approved=approved
    )


# ==========================================================
# ADD USER
# ==========================================================

@app.route("/add_user", methods=["POST"])
@role_required("admin")
def add_user():

    name = request.form["name"]
    username = request.form["username"]
    password = request.form["password"]
    role = request.form["role"]

    conn = get_db()

    try:

        conn.execute("""
            INSERT INTO users
            (name, username, password, role)
            VALUES (?, ?, ?, ?)
        """, (name, username, password, role))

        conn.commit()

        flash("User added successfully.", "success")

    except sqlite3.IntegrityError:

        flash("Username already exists.", "error")

    conn.close()

    return redirect(url_for("admin_dashboard"))


# ==========================================================
# DELETE USER
# ==========================================================

@app.route("/delete_user/<int:user_id>")
@role_required("admin")
def delete_user(user_id):

    if user_id == session["user_id"]:

        flash("You cannot delete your own account.", "error")

        return redirect(url_for("admin_dashboard"))

    conn = get_db()

    conn.execute("""
        DELETE FROM users
        WHERE id = ?
    """, (user_id,))

    conn.commit()
    conn.close()

    flash("User deleted.", "success")

    return redirect(url_for("admin_dashboard"))


# ==========================================================
# LOGOUT
# ==========================================================

@app.route("/logout")
def logout():

    session.clear()

    flash("You have been logged out.", "success")

    return redirect(url_for("login"))


# ==========================================================
# RUN APPLICATION
# ==========================================================

if __name__ == "__main__":

    initialize_database()

    app.run(debug=True)