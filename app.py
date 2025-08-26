from flask import Flask, request, redirect, url_for, render_template, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from packaging.version import Version
from datetime import datetime
from functools import wraps
from io import StringIO, BytesIO
import os
import json



# App Configuration
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'your_very_secret_key_here'
db = SQLAlchemy(app)

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    """Loads a user from the database for Flask-Login."""
    return User.query.get(int(user_id))


# -------------------- Prevent Caching --------------------
@app.after_request
def add_no_cache_headers(response):
    """Adds no-cache headers to all responses to prevent browser caching."""
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response


# -------------------- Custom Decorator --------------------

def admin_required(f):
    """A custom decorator to ensure only admin users can access a route."""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            return "Unauthorized Access", 403
        return f(*args, **kwargs)

    return decorated_function


# -------------------- Database Models --------------------

class User(db.Model, UserMixin):
    """User model for authentication."""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')

    def set_password(self, password):
        """Hashes the user's password."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Checks if the provided password is correct."""
        return check_password_hash(self.password_hash, password)


class Device(db.Model):
    """Device model to store firmware information."""
    id = db.Column(db.Integer, primary_key=True)
    manufacturer = db.Column(db.String(100), nullable=False)
    model = db.Column(db.String(100), unique=True, nullable=False)
    latest_firmware_version = db.Column(db.String(50), nullable=False)
    latest_firmware_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    is_certified = db.Column(db.Boolean, default=False)
    # New column for installation file title
    installation_file_title = db.Column(db.String(200), nullable=True)


# -------------------- Routes --------------------

# Regular User Home Page (requires login)
@app.route("/")
@login_required
def index():
    """Home page displaying devices based on user role and search filter."""
    model_filter = request.args.get('model')

    if current_user.role == 'admin':
        query = Device.query
    else:
        query = Device.query.filter_by(is_certified=True)

    if model_filter:
        query = query.filter(Device.model.ilike(f'%{model_filter}%'))

    devices = query.all()

    return render_template('index.html', devices=devices, model_filter=model_filter)


# Unified route for checking firmware via manual input or OCR
@app.route("/check_firmware", methods=['GET', 'POST'])
@login_required
def check_firmware():
    """Allows users to check a device's firmware version via manual input or image OCR."""
    result = None
    # Fetch all devices to be used for the autocomplete feature
    devices = Device.query.all()

    if request.method == 'POST':
        model = request.form.get('model')
        if not model:
            return "No model provided", 400

        installed_version = None

        # Check if an image was uploaded (for OCR)
        if 'firmware_image' in request.files and request.files['firmware_image'].filename != '':
            file = request.files['firmware_image']
            try:
                img = Image.open(io.BytesIO(file.read()))
                extracted_text = pytesseract.image_to_string(img)
                for word in extracted_text.split():
                    if '.' in word and word.replace('.', '').replace(',', '').isdigit():
                        installed_version = word.replace(',', '')
                        break
                if not installed_version:
                    result = {"error": "Could not extract a valid version from the image."}
            except Exception as e:
                result = {"error": f"An error occurred during OCR: {e}"}

        # Check if firmware version was manually typed
        elif 'installed_version' in request.form:
            installed_version = request.form['installed_version']

        if installed_version and not result:
            device = Device.query.filter_by(model=model).first()
            if device:
                # NEW LOGIC: Use direct string comparison
                status = "Up to date" if installed_version == device.latest_firmware_version else "Update required"

                result = {
                    "manufacturer": device.manufacturer,
                    "model": device.model,
                    "installed": installed_version,
                    "latest": device.latest_firmware_version,
                    "status": status,
                    "date": device.latest_firmware_date.strftime('%Y-%m-%d')
                }
            else:
                result = {"error": f"Model '{model}' not found"}

    return render_template("check.html", result=result, devices=devices)


# Admin Dashboard
@app.route("/admin")
@admin_required
def admin_dashboard():
    """Displays the admin dashboard with all devices."""
    devices = Device.query.all()
    return render_template('admin_dashboard.html', devices=devices)


# Admin route for adding a device with error handling for duplicates
@app.route("/admin/add", methods=['GET', 'POST'])
@admin_required
def add_device():
    """Route to add a new device."""
    error = None
    if request.method == 'POST':
        manufacturer = request.form['manufacturer']
        model = request.form['model']
        version = request.form['version']
        date_str = request.form['date']
        is_certified = 'is_certified' in request.form
        installation_file_title = request.form.get('installation_file_title', '')

        existing_device = Device.query.filter_by(model=model).first()
        if existing_device:
            error = f"Error: A device with model '{model}' already exists."
        else:
            try:
                date_obj = datetime.strptime(date_str, '%Y-%m-%d')
                new_device = Device(
                    manufacturer=manufacturer,
                    model=model,
                    latest_firmware_version=version,
                    latest_firmware_date=date_obj,
                    is_certified=is_certified,
                    installation_file_title=installation_file_title
                )
                db.session.add(new_device)
                db.session.commit()
                return redirect(url_for('admin_dashboard'))
            except Exception as e:
                error = f"Error adding device: {e}"
    return render_template("add_device.html", error=error)


# Admin route for updating a device
@app.route("/admin/update/<int:device_id>", methods=['GET', 'POST'])
@admin_required
def update_device(device_id):
    """Route to update an existing device."""
    device = Device.query.get_or_404(device_id)
    if request.method == 'POST':
        device.manufacturer = request.form['manufacturer']
        device.model = request.form['model']
        device.latest_firmware_version = request.form['version']
        device.latest_firmware_date = datetime.strptime(request.form['date'], '%Y-%m-%d')
        device.is_certified = 'is_certified' in request.form
        device.installation_file_title = request.form.get('installation_file_title', '')
        db.session.commit()
        return redirect(url_for('admin_dashboard'))

    return render_template("update_device.html", device=device)


# Admin route for deleting a device
@app.route("/admin/delete/<int:device_id>", methods=['POST'])
@admin_required
def delete_device(device_id):
    """Route to delete a device."""
    device = Device.query.get_or_404(device_id)
    db.session.delete(device)
    db.session.commit()
    return redirect(url_for('admin_dashboard'))


# User Management routes
@app.route("/admin/users")
@admin_required
def user_management():
    """Route to manage users."""
    users = User.query.all()
    return render_template("user_management.html", users=users)


@app.route("/admin/create_user", methods=['GET', 'POST'])
@admin_required
def create_user():
    """Route to create a new user."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return "User already exists!", 400

        new_user = User(username=username, role=role)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('user_management'))

    return render_template("create_user.html")


@app.route("/admin/delete_user/<int:user_id>", methods=['POST'])
@admin_required
def delete_user(user_id):
    """Route to delete a user."""
    user_to_delete = User.query.get_or_404(user_id)

    if user_to_delete.id == current_user.id:
        return "You cannot delete your own account.", 403

    if user_to_delete.role == 'admin':
        admin_count = User.query.filter_by(role='admin').count()
        if admin_count <= 1:
            return "Cannot delete the last administrator.", 403

    db.session.delete(user_to_delete)
    db.session.commit()
    return redirect(url_for('user_management'))


# Authentication Routes
@app.route("/login", methods=['GET', 'POST'])
def login():
    """Handles user login."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('index'))
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    """Logs the user out."""
    logout_user()
    return redirect(url_for('index'))


@app.route('/export_text')
@admin_required
def export_firmware_text():
    """Generates and serves a plain text file of the firmware list in a tabular format."""
    # Fetch devices and sort them by manufacturer
    devices = Device.query.order_by(Device.manufacturer).all()

    # Define column widths for a clean, tabular layout
    manufacturer_width = max(len("Manufacturer"), max(len(d.manufacturer) for d in devices) if devices else 0) + 2
    model_width = max(len("Model"), max(len(d.model) for d in devices) if devices else 0) + 2
    version_width = max(len("Latest Version"),
                        max(len(d.latest_firmware_version) for d in devices) if devices else 0) + 2
    # New column for installation file title
    file_title_width = max(len("Installation File"), max(
        len(d.installation_file_title) if d.installation_file_title else "" for d in devices) if devices else 0) + 2
    date_width = len("Release Date") + 2
    certified_width = len("Certified") + 2

    header = f"{'Manufacturer':<{manufacturer_width}}{'Model':<{model_width}}{'Latest Version':<{version_width}}{'Installation File':<{file_title_width}}{'Release Date':<{date_width}}{'Certified':<{certified_width}}\n"
    divider = "-" * (
                manufacturer_width + model_width + version_width + file_title_width + date_width + certified_width) + "\n"

    text_content = header + divider

    for device in devices:
        file_title = device.installation_file_title if device.installation_file_title else ""
        text_content += f"{device.manufacturer:<{manufacturer_width}}{device.model:<{model_width}}{device.latest_firmware_version:<{version_width}}{file_title:<{file_title_width}}{device.latest_firmware_date.strftime('%Y-%m-%d'):<{date_width}}{'Yes' if device.is_certified else 'No':<{certified_width}}\n"

    # Use BytesIO and encode the text to make it binary-compatible for send_file
    text_file = BytesIO()
    text_file.write(text_content.encode('utf-8'))
    text_file.seek(0)

    return send_file(
        text_file,
        mimetype='text/plain',
        as_attachment=True,
        download_name='firmware_report.txt'
    )


@app.route('/admin/backup')
@admin_required
def backup_database():
    """
    Creates a backup of the database file and serves it for download.
    This provides a simple manual backup solution for the administrator.
    """
    db_path = 'database.db'
    if not os.path.exists(db_path):
        return "Database file not found", 404

    try:
        # Prepare the file to be sent
        return send_file(
            db_path,
            mimetype='application/octet-stream',
            as_attachment=True,
            download_name=f'firmware_database_backup_{datetime.now().strftime("%Y%m%d_%H%M%S")}.db'
        )
    except Exception as e:
        return f"Error creating backup: {e}", 500


# -------------------- Main Application --------------------
def seed_admin():
    """Creates tables and a default admin user if they don't exist."""
    with app.app_context():
        db.create_all()
        admin_user = User.query.filter_by(username="admin").first()
        if not admin_user:
            admin_user = User(
                username="admin",
                password_hash=generate_password_hash("admin"),
                role="admin",
            )
            db.session.add(admin_user)
            db.session.commit()
            print("Seeded admin user: admin / admin")


if __name__ == "__main__":
    # If using Windows, may need to specify the path to the Tesseract executable
    # pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'
    seed_admin()
    app.run(host="0.0.0.0", port=5000, debug=True)
