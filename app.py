import os
import re
import secrets
import sqlite3
from datetime import date as date_cls, datetime, timedelta, timezone
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-only-change-me")
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=(
        os.environ.get("RAILWAY_ENVIRONMENT") is not None
        or os.environ.get("RENDER") is not None
    ),
)

DATABASE = os.environ.get("DATABASE_PATH", os.path.join(os.path.dirname(os.path.abspath(__file__)), "guidance.db"))

YEAR_LEVELS = ["Grade 11", "Grade 12", "1st Year", "2nd Year", "3rd Year", "4th Year", "5th Year"]

DEPARTMENTS = [
    "Senior High School",
    "College of Arts and Sciences",
    "College of Business and Accountancy",
    "College of Computer Studies",
    "College of Criminology",
    "College of Education",
    "College of Engineering",
    "College of Hospitality and Tourism Management",
    "College of Nursing",
]

CONTACT_PATTERN = re.compile(r"^\+?[0-9][0-9\s-]{6,15}$")

# Matches the min/max on the time input in book.html
OFFICE_OPEN = "08:00"
OFFICE_CLOSE = "17:00"

# Appointments on the same date must be at least this many minutes apart.
SLOT_GAP_MINUTES = 60

# The server may run in UTC (Render), so "today" and "now" use Philippine time.
LOCAL_TZ = timezone(timedelta(hours=8))

SLOT_TAKEN_MESSAGE = (
    "That time isn't available. Appointments must be at least 1 hour apart, "
    "so please pick a different time."
)


# ==========================================================
# DATABASE
# ==========================================================

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def ensure_column(cursor, table, column, definition):
    columns = [row["name"] for row in cursor.execute(f"PRAGMA table_info({table})").fetchall()]
    if column not in columns:
        cursor.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def initialize_database():
    db_dir = os.path.dirname(DATABASE)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL
        )
    """)

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

    for column in ("contact_number", "year_level", "department"):
        ensure_column(cursor, "users", column, "TEXT")
        ensure_column(cursor, "appointments", column, "TEXT")

    default_password = os.environ.get("DEFAULT_PASSWORD", "1234")
    defaults = [
        ("Juan Student", "student", "student"),
        ("Ms. Maria Counselor", "counselor", "counselor"),
        ("System Administrator", "admin", "admin"),
    ]
    for name, username, role in defaults:
        exists = cursor.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone()
        if exists is None:
            cursor.execute(
                "INSERT INTO users (name, username, password, role) VALUES (?, ?, ?, ?)",
                (name, username, generate_password_hash(default_password), role),
            )

    conn.commit()
    conn.close()


def verify_password(stored, provided):
    if stored.startswith(("scrypt:", "pbkdf2:")):
        return check_password_hash(stored, provided)
    return secrets.compare_digest(stored, provided)


# ==========================================================
# SCHEDULING HELPERS
# ==========================================================

def to_minutes(value):
    """'09:30' -> 570"""
    hours, minutes = value.split(":")[:2]
    return int(hours) * 60 + int(minutes)


def now_local():
    return datetime.now(LOCAL_TZ)


def validate_slot(date_str, time_str):
    """Return an error message if the date/time isn't acceptable, else None."""
    try:
        slot_date = datetime.strptime(date_str, "%Y-%m-%d").date()
        slot_time = datetime.strptime(time_str, "%H:%M").time()
    except ValueError:
        return "Please choose a valid date and time."

    minutes = slot_time.hour * 60 + slot_time.minute
    if not (to_minutes(OFFICE_OPEN) <= minutes <= to_minutes(OFFICE_CLOSE)):
        return "Please choose a time between 8:00 AM and 5:00 PM."

    if datetime.combine(slot_date, slot_time, tzinfo=LOCAL_TZ) < now_local():
        return "That date and time has already passed. Please choose a future time."

    return None


def year_rank(year_level):
    """Position of a year level in YEAR_LEVELS; unknown/empty goes last."""
    return YEAR_LEVELS.index(year_level) if year_level in YEAR_LEVELS else len(YEAR_LEVELS)


# ==========================================================
# CSRF PROTECTION
# ==========================================================

def get_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(16)
    return session["csrf_token"]


app.jinja_env.globals["csrf_token"] = get_csrf_token


@app.before_request
def csrf_protect():
    if request.method == "POST":
        token = request.form.get("csrf_token", "")
        if not token or not secrets.compare_digest(token, session.get("csrf_token", "")):
            abort(400)


# ==========================================================
# MODELS
# ==========================================================

class User:

    def __init__(self, id, name, username, role):
        self.id = id
        self.name = name
        self.username = username
        self.role = role

    @staticmethod
    def login(username, password):
        conn = get_db()
        row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

        if row and verify_password(row["password"], password):
            if not row["password"].startswith(("scrypt:", "pbkdf2:")):
                conn.execute(
                    "UPDATE users SET password = ? WHERE id = ?",
                    (generate_password_hash(password), row["id"]),
                )
                conn.commit()
            conn.close()
            return User(row["id"], row["name"], row["username"], row["role"])

        conn.close()
        return None

    @staticmethod
    def create(name, username, password, role="student", contact_number=None, year_level=None, department=None):
        conn = get_db()
        try:
            conn.execute(
                """
                INSERT INTO users (name, username, password, role, contact_number, year_level, department)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (name, username, generate_password_hash(password), role, contact_number, year_level, department),
            )
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False
        finally:
            conn.close()

    @staticmethod
    def get_profile(user_id):
        conn = get_db()
        row = conn.execute(
            "SELECT contact_number, year_level, department FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        conn.close()
        return row


APPOINTMENT_SELECT = """
    SELECT
        appointments.id,
        appointments.date,
        appointments.time,
        appointments.reason,
        appointments.status,
        COALESCE(appointments.contact_number, users.contact_number) AS contact_number,
        COALESCE(appointments.year_level, users.year_level) AS year_level,
        COALESCE(appointments.department, users.department) AS department,
        users.name AS student_name
    FROM appointments
    JOIN users ON appointments.student_id = users.id
"""


class Appointment:

    @staticmethod
    def _has_conflict(conn, date, time, exclude_id=0):
        """True if another active appointment on this date is less than
        SLOT_GAP_MINUTES away from `time`. Rejected ones don't block the slot."""
        rows = conn.execute(
            "SELECT time FROM appointments WHERE date = ? AND status != 'Rejected' AND id != ?",
            (date, exclude_id),
        ).fetchall()
        wanted = to_minutes(time)
        for row in rows:
            try:
                if abs(to_minutes(row["time"]) - wanted) < SLOT_GAP_MINUTES:
                    return True
            except ValueError:
                continue
        return False

    @staticmethod
    def create(student_id, date, time, reason, contact_number, year_level, department):
        """Returns True if booked, False if the slot conflicts with another."""
        conn = get_db()
        try:
            # IMMEDIATE takes the write lock now, so two students can't both
            # pass the conflict check and then both insert.
            conn.execute("BEGIN IMMEDIATE")
            if Appointment._has_conflict(conn, date, time):
                conn.rollback()
                return False
            conn.execute(
                """
                INSERT INTO appointments
                (student_id, date, time, reason, status, contact_number, year_level, department)
                VALUES (?, ?, ?, ?, 'Pending', ?, ?, ?)
                """,
                (student_id, date, time, reason, contact_number, year_level, department),
            )
            conn.execute(
                "UPDATE users SET contact_number = ?, year_level = ?, department = ? WHERE id = ?",
                (contact_number, year_level, department, student_id),
            )
            conn.commit()
            return True
        finally:
            conn.close()

    @staticmethod
    def get_student_appointments(student_id):
        conn = get_db()
        rows = conn.execute(
            APPOINTMENT_SELECT + " WHERE appointments.student_id = ? ORDER BY appointments.date, appointments.time",
            (student_id,),
        ).fetchall()
        conn.close()
        return rows

    @staticmethod
    def get_for_student(appointment_id, student_id):
        conn = get_db()
        row = conn.execute(
            APPOINTMENT_SELECT + " WHERE appointments.id = ? AND appointments.student_id = ?",
            (appointment_id, student_id),
        ).fetchone()
        conn.close()
        return row

    @staticmethod
    def get_by_id(appointment_id):
        conn = get_db()
        row = conn.execute(
            APPOINTMENT_SELECT + " WHERE appointments.id = ?",
            (appointment_id,),
        ).fetchone()
        conn.close()
        return row

    @staticmethod
    def get_all_appointments(order="date"):
        """order='booked' -> first to book on top; order='date' -> by appointment date."""
        order_sql = "appointments.id" if order == "booked" else "appointments.date, appointments.time"
        conn = get_db()
        rows = conn.execute(APPOINTMENT_SELECT + " ORDER BY " + order_sql).fetchall()
        conn.close()
        return rows

    @staticmethod
    def update_status(appointment_id, status):
        conn = get_db()
        conn.execute("UPDATE appointments SET status = ? WHERE id = ?", (status, appointment_id))
        conn.commit()
        conn.close()

    @staticmethod
    def reschedule(appointment_id, date, time, student_id=None):
        """Move an appointment to a new slot.

        Returns 'ok', 'conflict' (slot too close to another appointment) or
        'unavailable' (not found / not editable).

        With student_id: ownership is enforced and the status resets to Pending.
        Without it (staff): any Pending/Approved appointment, status unchanged.
        """
        conn = get_db()
        try:
            conn.execute("BEGIN IMMEDIATE")
            if Appointment._has_conflict(conn, date, time, appointment_id):
                conn.rollback()
                return "conflict"

            if student_id is not None:
                cursor = conn.execute(
                    """
                    UPDATE appointments
                    SET date = ?, time = ?, status = 'Pending'
                    WHERE id = ? AND student_id = ? AND status IN ('Pending', 'Approved')
                    """,
                    (date, time, appointment_id, student_id),
                )
            else:
                cursor = conn.execute(
                    """
                    UPDATE appointments
                    SET date = ?, time = ?
                    WHERE id = ? AND status IN ('Pending', 'Approved')
                    """,
                    (date, time, appointment_id),
                )
            conn.commit()
            return "ok" if cursor.rowcount > 0 else "unavailable"
        finally:
            conn.close()

    @staticmethod
    def update_for_student(appointment_id, student_id, date, time, reason):
        """Student edits their own appointment.

        Returns 'rescheduled' (date/time changed, back to Pending), 'updated'
        (only the reason changed), 'conflict' or 'unavailable'.
        """
        conn = get_db()
        try:
            conn.execute("BEGIN IMMEDIATE")
            current = conn.execute(
                """
                SELECT date, time FROM appointments
                WHERE id = ? AND student_id = ? AND status IN ('Pending', 'Approved')
                """,
                (appointment_id, student_id),
            ).fetchone()
            if current is None:
                conn.rollback()
                return "unavailable"

            schedule_changed = current["date"] != date or current["time"] != time

            if schedule_changed:
                if Appointment._has_conflict(conn, date, time, appointment_id):
                    conn.rollback()
                    return "conflict"
                conn.execute(
                    "UPDATE appointments SET date = ?, time = ?, reason = ?, status = 'Pending' WHERE id = ?",
                    (date, time, reason, appointment_id),
                )
            else:
                conn.execute(
                    "UPDATE appointments SET reason = ? WHERE id = ?",
                    (reason, appointment_id),
                )

            conn.commit()
            return "rescheduled" if schedule_changed else "updated"
        finally:
            conn.close()

    @staticmethod
    def cancel(appointment_id, student_id):
        conn = get_db()
        cursor = conn.execute(
            """
            DELETE FROM appointments
            WHERE id = ? AND student_id = ? AND status IN ('Pending', 'Approved')
            """,
            (appointment_id, student_id),
        )
        conn.commit()
        changed = cursor.rowcount > 0
        conn.close()
        return changed


def count_by_status(appointments):
    counts = {"Pending": 0, "Approved": 0, "Rejected": 0}
    for appointment in appointments:
        counts[appointment["status"]] = counts.get(appointment["status"], 0) + 1
    return counts


# ==========================================================
# DECORATORS
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
# AUTH
# ==========================================================

@app.route("/", methods=["GET", "POST"])
def login():
    if "user_id" in session and request.method == "GET":
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = User.login(username, password)

        if user:
            csrf = session.get("csrf_token")
            session.clear()
            session["csrf_token"] = csrf or secrets.token_hex(16)
            session["user_id"] = user.id
            session["name"] = user.name
            session["role"] = user.role
            return redirect(url_for("dashboard"))

        flash("Invalid username or password.", "error")

    return render_template("login.html")


@app.route("/signup", methods=["GET", "POST"])
def signup():
    context = {"year_levels": YEAR_LEVELS, "departments": DEPARTMENTS}

    if request.method == "POST":
        form = {
            "name": request.form.get("name", "").strip(),
            "username": request.form.get("username", "").strip(),
            "contact_number": request.form.get("contact_number", "").strip(),
            "year_level": request.form.get("year_level", ""),
            "department": request.form.get("department", ""),
        }
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        error = None
        if not all(form.values()) or not password or not confirm_password:
            error = "Please complete all fields."
        elif not CONTACT_PATTERN.match(form["contact_number"]):
            error = "Please enter a valid contact number."
        elif form["year_level"] not in YEAR_LEVELS or form["department"] not in DEPARTMENTS:
            error = "Please choose a valid year level and department."
        elif password != confirm_password:
            error = "Passwords do not match."
        elif len(password) < 6:
            error = "Password must be at least 6 characters."
        elif not User.create(
            form["name"], form["username"], password, "student",
            form["contact_number"], form["year_level"], form["department"],
        ):
            error = "That username is already taken."

        if error:
            flash(error, "error")
            return render_template("signup.html", form=form, **context)

        flash("Account created! You can now log in.", "success")
        return redirect(url_for("login"))

    return render_template("signup.html", form={}, **context)


@app.route("/dashboard")
@login_required
def dashboard():
    role = session.get("role")
    if role == "student":
        return redirect(url_for("student_dashboard"))
    if role == "counselor":
        return redirect(url_for("counselor_dashboard"))
    if role == "admin":
        return redirect(url_for("admin_dashboard"))
    return redirect(url_for("login"))


# ==========================================================
# STUDENT
# ==========================================================

@app.route("/student")
@role_required("student")
def student_dashboard():
    appointments = Appointment.get_student_appointments(session["user_id"])
    return render_template("student.html", appointments=appointments, counts=count_by_status(appointments))


@app.route("/book", methods=["GET", "POST"])
@role_required("student")
def book_appointment():
    profile = User.get_profile(session["user_id"])

    # Year level and department come from the student's profile and cannot be
    # changed here. If a value was never saved, the student may pick it once.
    locked_year = profile["year_level"] if profile and profile["year_level"] in YEAR_LEVELS else None
    locked_department = profile["department"] if profile and profile["department"] in DEPARTMENTS else None

    context = {
        "year_levels": YEAR_LEVELS,
        "departments": DEPARTMENTS,
        "lock_year": locked_year is not None,
        "lock_department": locked_department is not None,
    }

    if request.method == "POST":
        form = {
            "date": request.form.get("date", ""),
            "time": request.form.get("time", ""),
            "reason": request.form.get("reason", "").strip(),
            "contact_number": request.form.get("contact_number", "").strip(),
            "year_level": locked_year or request.form.get("year_level", ""),
            "department": locked_department or request.form.get("department", ""),
        }

        error = None
        if not all(form.values()):
            error = "Please complete all fields."
        elif not CONTACT_PATTERN.match(form["contact_number"]):
            error = "Please enter a valid contact number."
        elif form["year_level"] not in YEAR_LEVELS or form["department"] not in DEPARTMENTS:
            error = "Please choose a valid year level and department."
        else:
            error = validate_slot(form["date"], form["time"])

        if error:
            flash(error, "error")
            return render_template("book.html", form=form, **context)

        booked = Appointment.create(
            session["user_id"], form["date"], form["time"], form["reason"],
            form["contact_number"], form["year_level"], form["department"],
        )
        if not booked:
            flash(SLOT_TAKEN_MESSAGE, "error")
            return render_template("book.html", form=form, **context)

        flash("Appointment request submitted successfully!", "success")
        return redirect(url_for("student_dashboard"))

    form = dict(profile) if profile else {}
    return render_template("book.html", form=form, **context)


@app.route("/edit/<int:appointment_id>", methods=["GET", "POST"])
@role_required("student")
def edit_appointment(appointment_id):
    appointment = Appointment.get_for_student(appointment_id, session["user_id"])

    if appointment is None:
        abort(404)
    if appointment["status"] not in ("Pending", "Approved"):
        flash("Only pending or approved appointments can be edited.", "error")
        return redirect(url_for("student_dashboard"))

    if request.method == "POST":
        form = {
            "date": request.form.get("date", ""),
            "time": request.form.get("time", ""),
            "reason": request.form.get("reason", "").strip(),
        }

        schedule_changed = form["date"] != appointment["date"] or form["time"] != appointment["time"]

        error = None
        if not all(form.values()):
            error = "Please complete all fields."
        elif len(form["reason"]) > 1000:
            error = "Reason is too long (1000 characters max)."
        elif schedule_changed:
            # Only re-check the date/time if the student actually changed it,
            # so the reason of an older appointment can still be edited.
            error = validate_slot(form["date"], form["time"])

        if error:
            flash(error, "error")
            return render_template("edit.html", appointment=appointment, form=form)

        result = Appointment.update_for_student(
            appointment_id, session["user_id"], form["date"], form["time"], form["reason"]
        )

        if result == "conflict":
            flash(SLOT_TAKEN_MESSAGE, "error")
            return render_template("edit.html", appointment=appointment, form=form)
        if result == "rescheduled":
            flash("Appointment updated. It is now pending counselor approval.", "success")
        elif result == "updated":
            flash("Appointment updated.", "success")
        else:
            flash("This appointment can no longer be edited.", "error")
        return redirect(url_for("student_dashboard"))

    form = {
        "date": appointment["date"],
        "time": appointment["time"],
        "reason": appointment["reason"],
    }
    return render_template("edit.html", appointment=appointment, form=form)


@app.route("/cancel/<int:appointment_id>", methods=["POST"])
@role_required("student")
def cancel_appointment(appointment_id):
    if Appointment.cancel(appointment_id, session["user_id"]):
        flash("Appointment deleted.", "success")
    else:
        flash("This appointment can no longer be deleted.", "error")
    return redirect(url_for("student_dashboard"))


# ==========================================================
# RESCHEDULE (counselor/admin; students use Edit)
# ==========================================================

@app.route("/reschedule/<int:appointment_id>", methods=["GET", "POST"])
@login_required
def reschedule_appointment(appointment_id):
    role = session.get("role")
    if role not in ("student", "counselor", "admin"):
        abort(403)

    is_student = role == "student"
    student_id = session["user_id"] if is_student else None

    if is_student:
        appointment = Appointment.get_for_student(appointment_id, session["user_id"])
    else:
        appointment = Appointment.get_by_id(appointment_id)

    if appointment is None:
        abort(404)
    if appointment["status"] not in ("Pending", "Approved"):
        flash("Only pending or approved appointments can be rescheduled.", "error")
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        form = {
            "date": request.form.get("date", ""),
            "time": request.form.get("time", ""),
        }

        error = validate_slot(form["date"], form["time"])
        if not error and form["date"] == appointment["date"] and form["time"] == appointment["time"]:
            error = "That is already the current schedule."

        if error:
            flash(error, "error")
            return render_template("reschedule.html", appointment=appointment, form=form)

        result = Appointment.reschedule(appointment_id, form["date"], form["time"], student_id)

        if result == "conflict":
            flash(SLOT_TAKEN_MESSAGE, "error")
            return render_template("reschedule.html", appointment=appointment, form=form)
        if result == "ok":
            if is_student:
                flash("Appointment rescheduled. It is now pending counselor approval.", "success")
            else:
                flash("Appointment rescheduled.", "success")
        else:
            flash("This appointment can no longer be rescheduled.", "error")
        return redirect(url_for("dashboard"))

    form = {"date": appointment["date"], "time": appointment["time"]}
    return render_template("reschedule.html", appointment=appointment, form=form)


# ==========================================================
# COUNSELOR
# ==========================================================

@app.route("/counselor")
@role_required("counselor")
def counselor_dashboard():
    appointments = Appointment.get_all_appointments(order="date")
    return render_template("counselor.html", appointments=appointments, counts=count_by_status(appointments))


@app.route("/approve/<int:appointment_id>", methods=["POST"])
@role_required("counselor")
def approve_appointment(appointment_id):
    Appointment.update_status(appointment_id, "Approved")
    flash("Appointment approved.", "success")
    return redirect(url_for("counselor_dashboard"))


@app.route("/reject/<int:appointment_id>", methods=["POST"])
@role_required("counselor")
def reject_appointment(appointment_id):
    Appointment.update_status(appointment_id, "Rejected")
    flash("Appointment rejected.", "success")
    return redirect(url_for("counselor_dashboard"))


# ==========================================================
# ADMIN
# ==========================================================

@app.route("/admin")
@role_required("admin")
def admin_dashboard():
    selected_year = request.args.get("year", "")
    selected_order = request.args.get("order", "booked")
    if selected_year not in YEAR_LEVELS:
        selected_year = ""
    if selected_order not in ("booked", "date", "year"):
        selected_order = "booked"

    conn = get_db()
    all_users = conn.execute("SELECT * FROM users").fetchall()
    conn.close()

    # Users: sorted by year level (Grade 11 ... 5th Year), then name.
    # Staff accounts have no year level, so they come last.
    users = sorted(all_users, key=lambda u: (year_rank(u["year_level"]), (u["name"] or "").lower()))
    if selected_year:
        users = [u for u in users if u["year_level"] == selected_year]

    # Appointments: "booked" = first to book on top (by id).
    everything = Appointment.get_all_appointments(order="date" if selected_order == "date" else "booked")
    counts = count_by_status(everything)

    appointments = list(everything)
    if selected_order == "year":
        # sorted() is stable, so booking order is kept within each year level
        appointments.sort(key=lambda a: year_rank(a["year_level"]))
    if selected_year:
        appointments = [a for a in appointments if a["year_level"] == selected_year]

    return render_template(
        "admin.html",
        users=users,
        appointments=appointments,
        total_users=len(all_users),
        total_appointments=len(everything),
        pending=counts["Pending"],
        approved=counts["Approved"],
        year_levels=YEAR_LEVELS,
        departments=DEPARTMENTS,
        selected_year=selected_year,
        selected_order=selected_order,
    )


@app.route("/add_user", methods=["POST"])
@role_required("admin")
def add_user():
    name = request.form.get("name", "").strip()
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    role = request.form.get("role", "student")

    if not name or not username or len(password) < 6 or role not in ("student", "counselor", "admin"):
        flash("Please fill in all fields. Passwords need at least 6 characters.", "error")
    elif User.create(name, username, password, role):
        flash("User added successfully.", "success")
    else:
        flash("Username already exists.", "error")

    return redirect(url_for("admin_dashboard"))


@app.route("/delete_user/<int:user_id>", methods=["POST"])
@role_required("admin")
def delete_user(user_id):
    if user_id == session["user_id"]:
        flash("You cannot delete your own account.", "error")
        return redirect(url_for("admin_dashboard"))

    conn = get_db()
    conn.execute("DELETE FROM appointments WHERE student_id = ?", (user_id,))
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()

    flash("User deleted.", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


@app.route("/health")
def health():
    return {"status": "ok"}


@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    return response


initialize_database()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=os.environ.get("FLASK_DEBUG") == "1")