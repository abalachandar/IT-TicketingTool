# app.py
from flask import Flask, request, render_template, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from dotenv import load_dotenv
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Load environment
load_dotenv()

app = Flask(__name__)
# Config
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret')

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Models


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(
    db.String(50),
    nullable=False,
     default='user')  # user, agent, supervisor
    department = db.Column(db.String(100))
    location = db.Column(db.String(100))


class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    parent_id = db.Column(db.Integer, db.ForeignKey('category.id'))


class Ticket(db.Model):
    id = db.Column(db.String(20), primary_key=True)
    created_at = db.Column(
    db.DateTime,
    default=datetime.utcnow,
     nullable=False)
    subject = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(100), nullable=False)
    priority = db.Column(db.String(3), nullable=False)
    status = db.Column(db.String(50), default='New', nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    assigned_to = db.Column(db.Integer, db.ForeignKey('user.id'))
    sla_response_target = db.Column(db.DateTime)
    sla_resolution_target = db.Column(db.DateTime)
    escalation_level = db.Column(db.Integer, default=0)
    response = db.Column(db.Text)


class KnowledgeBase(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'))
    approved_by = db.Column(db.Integer, db.ForeignKey('user.id'))


class Log(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(
    db.String(20),
    db.ForeignKey('ticket.id'),
     nullable=False)
    action = db.Column(db.String(100), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Ensure DB exists
with app.app_context():
    db.create_all()

# Utility functions


def send_email(to_email, subject, body):
    sender = os.getenv('EMAIL_SENDER')
    password = os.getenv('EMAIL_PASSWORD')
    smtp_server = os.getenv('SMTP_SERVER')
    smtp_port = int(os.getenv('SMTP_PORT', 587))
    if not (sender and password and smtp_server):
        app.logger.info("Email not sent: SMTP config incomplete.")
        return False
    try:
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(sender, password)
        msg = MIMEMultipart()
        msg['From'] = sender
        msg['To'] = to_email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))
        server.sendmail(sender, to_email, msg.as_string())
        server.quit()
        return True
    except Exception as e:
        app.logger.error(f"Error sending email: {e}")
        return False


def generate_ticket_id():
    # Format: YYYY-MM-NNNNNN (increment)
    prefix = datetime.utcnow().strftime("%Y-%m")
    # Count tickets this month to produce simple sequence
    like = f"{prefix}-%"
    count = Ticket.query.filter(Ticket.id.like(like)).count()
    seq = count + 1
    return f"{prefix}-{seq:06d}"


def categorize_ticket(subject):
    lower_subject = (subject or "").lower()
    if any(word in lower_subject for word in ['password', 'login', 'access']):
        return 'IT - Access Management'
    elif any(word in lower_subject for word in ['printer', 'laptop', 'desktop', 'hardware']):
        return 'IT - Hardware'
    elif any(word in lower_subject for word in ['office space', 'parking', 'supplies', 'facility']):
        return 'Admin - Facilities'
    return 'Uncategorized'


def calculate_priority(impact, urgency):
    impact = (impact or '').lower()
    urgency = (urgency or '').lower()
    if impact == 'high' and urgency in ['critical', 'high']:
        return 'P1'
    if (impact == 'high' and urgency == 'medium') or (
        impact == 'medium' and urgency == 'critical'):
        return 'P2'
    if (impact == 'medium' and urgency in ['high', 'medium']) or (
        impact == 'low' and urgency == 'critical'):
        return 'P3'
    return 'P4'


def route_ticket(category, priority):
    # Simple routing: choose first matching agent by role/department
    if category.startswith('IT'):
        # try L2 for P1/P2
        if priority in ['P1', 'P2']:
            user = User.query.filter_by(
    role='agent', department='IT L2').first()
            if user:
                return user.id
        # fallback L1
        user = User.query.filter_by(role='agent', department='IT L1').first()
        if user:
            return user.id
    elif category.startswith('Admin'):
        user = User.query.filter_by(role='agent', department='Admin').first()
        if user:
            return user.id
    # no agent found
    return None

# Escalation check (simple; can be run on cron or background thread)


def check_escalation():
    now = datetime.utcnow()
    tickets = Ticket.query.filter(
        Ticket.status.notin_(['Closed', 'Cancelled'])).all()
    for t in tickets:
        if t.sla_response_target and now > t.sla_response_target:
            if t.escalation_level < 3:
                t.escalation_level += 1
                t.status = 'Escalated'
                db.session.add(t)
                # email a supervisor placeholder
                send_email(
    os.getenv('EMAIL_SENDER'), f'Ticket {
        t.id} Escalated', f'Ticket {
            t.id} breached response SLA.')
    db.session.commit()

# Routes


@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        pw = request.form['password']
        role = request.form.get('role', 'user')
        dept = request.form.get('department', '')
        if User.query.filter_by(email=email).first():
            flash('Email already registered')
            return redirect(url_for('register'))
        user = User(
    name=name,
    email=email,
    password=generate_password_hash(pw),
    role=role,
     department=dept)
        db.session.add(user)
        db.session.commit()
        flash('Registered. Please login.')
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        pw = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, pw):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Invalid credentials')
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'support':
        tickets = Ticket.query.filter_by(assigned_to=current_user.id).all()
        return render_template('support_dashboard.html', tickets=tickets)
    elif current_user.role == 'admin':
        tickets = Ticket.query.all()
        users = User.query.all()
        users_map = {u.id: u.name for u in users}
        return render_template('admin.html', tickets=tickets, users=users, users_map=users_map)
    else:
        tickets = Ticket.query.filter_by(user_id=current_user.id).all()
        return render_template('user_dashboard.html', tickets=tickets)


@app.route('/create_ticket', methods=['GET', 'POST'])
@login_required
def create_ticket():
    if current_user.role not in ['user', 'admin', 'support']:
        flash('Access denied')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        subject = request.form['subject']
        description = request.form['description']
        impact = request.form.get('impact', 'low')
        urgency = request.form.get('urgency', 'low')
        category = categorize_ticket(subject)
        priority = calculate_priority(impact, urgency)
        ticket_id = generate_ticket_id()

        # 🧠 Auto-assign logic: find first available support staff
        support_user = User.query.filter_by(role='support').first()

        new_ticket = Ticket(
            id=ticket_id,
            subject=subject,
            description=description,
            category=category,
            priority=priority,
            status='Open',
            user_id=current_user.id,
            assigned_to=support_user.id if support_user else None
        )

        if support_user:
            new_ticket.sla_response_target = datetime.utcnow() + timedelta(hours=1)
            assigned_name = support_user.name
        else:
            assigned_name = 'Unassigned'

        db.session.add(new_ticket)
        db.session.commit()

        # Notify the user
        send_email(
            current_user.email,
            f'Ticket {ticket_id} Created',
            f"Your ticket has been created and assigned to: {assigned_name}."
        )

        # Notify the support staff
        if support_user:
            send_email(
                support_user.email,
                f"New Ticket Assigned: {ticket_id}",
                f"A new ticket '{subject}' has been assigned to you.\n\nDescription:\n{description}"
            )

        flash(f"Ticket {ticket_id} created and assigned to {assigned_name}.")
        return redirect(url_for('dashboard'))

    return render_template('create_ticket.html')


@app.route('/ticket/<ticket_id>')
@login_required
def view_ticket(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)
    return render_template('ticket_view.html', ticket=ticket)


@app.route('/ticket/<ticket_id>/resolve', methods=['POST'])
@login_required
def resolve_ticket(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)
    if current_user.role not in [
    'agent',
     'supervisor'] and current_user.id != ticket.user_id:
        flash('Access denied')
        return redirect(url_for('dashboard'))
    ticket.status = 'Resolved'
    db.session.commit()
    if ticket.user_id:
        user = User.query.get(ticket.user_id)
        if user:
            send_email(
    user.email,
    f'Ticket {ticket_id} Resolved',
     'Please confirm resolution.')
    flash('Ticket resolved')
    return redirect(url_for('view_ticket', ticket_id=ticket_id))

# Simple API endpoint example


@app.route('/api/tickets', methods=['POST'])
def api_create_ticket():
    data = request.json or {}
    subject = data.get('subject', 'No subject')
    description = data.get('description', '')
    impact = data.get('impact', 'low')
    urgency = data.get('urgency', 'low')
    category = categorize_ticket(subject)
    priority = calculate_priority(impact, urgency)
    ticket_id = generate_ticket_id()
    new_ticket = Ticket(
        id=ticket_id,
        subject=subject,
        description=description,
        category=category,
        priority=priority,
        status='Open',
        user_id=data.get('user_id', None) or 0
    )
    new_ticket.assigned_to = route_ticket(category, priority)
    if new_ticket.assigned_to:
        new_ticket.sla_response_target = datetime.utcnow() + timedelta(hours=1)
    db.session.add(new_ticket)
    db.session.commit()
    return jsonify({'id': ticket_id}), 201

@app.route('/update_ticket/<ticket_id>', methods=['GET', 'POST'])
@login_required
def update_ticket(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)

    # Restrict update access
    if current_user.role not in ['support', 'admin']:
        flash('Access denied: only support and admin can update tickets.')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        new_status = request.form.get('status')
        new_priority = request.form.get('priority')
        response_text = request.form.get('response', '')

        # Update fields
        if new_status:
            ticket.status = new_status
        if new_priority:
            ticket.priority = new_priority

        # Optional: add response to logs
        if response_text:
            log = Log(ticket_id=ticket.id, action=f"Response: {response_text}", user_id=current_user.id)
            db.session.add(log)

        db.session.commit()

        # Email user notification
        user = User.query.get(ticket.user_id)
        if user:
            send_email(
                user.email,
                f"Ticket {ticket.id} Updated",
                f"Your ticket '{ticket.subject}' has been updated.\n\nStatus: {ticket.status}\nPriority: {ticket.priority}\nResponse: {response_text}"
            )

        flash(f"Ticket {ticket.id} updated successfully.", "success")
        return redirect(url_for('dashboard'))

    return render_template('update_ticket.html', ticket=ticket)

@app.route('/assign_ticket/<ticket_id>', methods=['GET', 'POST'])
@login_required
def assign_ticket(ticket_id):
    if current_user.role != 'admin':
        flash("Access denied: only admins can assign tickets.", "danger")
        return redirect(url_for('dashboard'))

    ticket = Ticket.query.get_or_404(ticket_id)
    users = User.query.all()

    if request.method == 'POST':
        assigned_email = request.form.get('assigned_to')
        user = User.query.filter_by(email=assigned_email).first()
        if user:
            ticket.assigned_to = user.id   # ✅ store user.id, not email
            db.session.commit()
            flash(f"Ticket {ticket.id} assigned to {user.email}.", "success")
            return redirect(url_for('view_ticket', ticket_id=ticket.id))
        else:
            flash("User not found.", "danger")

    return render_template('assign_ticket.html', ticket=ticket, users=users)


if __name__ == '__main__':
    # optional: run an initial escalation check on startup
    with app.app_context():
        check_escalation()
    app.run(debug=True, host='127.0.0.1', port=5000)

