from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from .models import save_message, get_messages
from functools import wraps

main = Blueprint('main', __name__)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            flash('Please log in to access this page.', 'danger')
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated_function

@main.route('/')
def index():
    return render_template('index.html')

@main.route('/chat', methods=['GET', 'POST'])
@login_required
def chat():
    if request.method == 'POST':
        receiver_id = request.form['receiver_id']
        message = request.form['message']
        ttl = request.form.get('ttl')  # Optional TTL in seconds
        save_message(session['user'], receiver_id, message, ttl)
        flash('Message sent!', 'success')
    messages = get_messages(session['user'])
    return render_template('chat.html', messages=messages)
