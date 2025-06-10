from flask import Blueprint, render_template, request, redirect, url_for, session, flash, jsonify
from .crypto import StealthCipher
from .models import User, Message
import time
import json
from functools import wraps

main = Blueprint('main', __name__)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('main.login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

@main.route('/')
def index():
    if 'user' not in session:
        return redirect(url_for('main.login'))
    return redirect(url_for('main.chat'))

@main.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        if not email or not password:
            flash('Email and password are required')
            return redirect(url_for('main.login'))
        
        try:
            # Authenticate with Firebase
            auth = current_app.config['FIREBASE_AUTH']
            user = auth.sign_in_with_email_and_password(email, password)
            
            # Generate encryption keys from password
            enc_key, hmac_key, salt = StealthCipher.generate_keys_from_password(password)
            
            # Store minimal user info in session
            session['user'] = {
                'uid': user['localId'],
                'email': email,
                'keys': {
                    'enc_key': enc_key.hex(),
                    'hmac_key': hmac_key.hex(),
                    'salt': salt.hex()
                },
                'last_activity': time.time()
            }
            
            # Set session as permanent
            session.permanent = True
            
            next_page = request.args.get('next')
            return redirect(next_page or url_for('main.chat'))
        except Exception as e:
            flash('Login failed. Please check your credentials.')
    
    return render_template('login.html')

@main.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if not email or not password:
            flash('Email and password are required')
            return redirect(url_for('main.register'))
        
        if password != confirm_password:
            flash('Passwords do not match')
            return redirect(url_for('main.register'))
        
        try:
            auth = current_app.config['FIREBASE_AUTH']
            user = auth.create_user_with_email_and_password(email, password)
            
            flash('Registration successful! Please login.')
            return redirect(url_for('main.login'))
        except Exception as e:
            error_msg = json.loads(e.args[1])['error']['message']
            flash(f'Registration failed: {error_msg}')
    
    return render_template('register.html')

@main.route('/chat', methods=['GET', 'POST'])
@login_required
def chat():
    user_info = session['user']
    db = current_app.config['FIREBASE_DB']
    
    # Initialize cipher with user's keys
    cipher = StealthCipher(
        bytes.fromhex(user_info['keys']['enc_key']),
        bytes.fromhex(user_info['keys']['hmac_key'])
    )
    
    if request.method == 'POST':
        message_content = request.form.get('message')
        recipient_email = request.form.get('recipient')
        
        if not message_content or not recipient_email:
            flash('Recipient and message are required')
            return redirect(url_for('main.chat'))
        
        try:
            # Get recipient UID
            auth = current_app.config['FIREBASE_AUTH']
            recipient = auth.get_account_info(recipient_email)
            recipient_uid = recipient['users'][0]['localId']
            
            # Encrypt the message
            encrypted_message = cipher.encrypt(message_content)
            
            # Create and save message
            message = Message(
                sender_id=user_info['uid'],
                recipient_id=recipient_uid,
                encrypted_content=encrypted_message,
                timestamp=int(time.time()),
                metadata={
                    'iv': True,  # IV is included in the encrypted payload
                    'hmac': True
                }
            )
            
            db.child('messages').push(message.to_dict())
            
            flash('Message sent securely!')
        except Exception as e:
            flash('Failed to send message. Recipient may not exist.')
    
    # Get messages
    messages = []
    try:
        # Get received messages
        received_msgs = db.child('messages') \
                         .order_by_child('recipient_id') \
                         .equal_to(user_info['uid']) \
                         .get()
        
        # Get sent messages
        sent_msgs = db.child('messages') \
                      .order_by_child('sender_id') \
                      .equal_to(user_info['uid']) \
                      .get()
        
        # Process received messages
        for msg in received_msgs.each():
            try:
                decrypted_content = cipher.decrypt(msg.val()['content'])
                messages.append({
                    'id': msg.key(),
                    'content': decrypted_content,
                    'sender': msg.val()['sender_id'],
                    'timestamp': msg.val()['timestamp'],
                    'direction': 'incoming'
                })
            except Exception as e:
                continue
        
        # Process sent messages
        for msg in sent_msgs.each():
            try:
                decrypted_content = cipher.decrypt(msg.val()['content'])
                messages.append({
                    'id': msg.key(),
                    'content': decrypted_content,
                    'recipient': msg.val()['recipient_id'],
                    'timestamp': msg.val()['timestamp'],
                    'direction': 'outgoing'
                })
            except Exception as e:
                continue
        
        # Sort messages by timestamp
        messages.sort(key=lambda x: x['timestamp'], reverse=True)
        
    except Exception as e:
        current_app.logger.error(f"Error fetching messages: {str(e)}")
        flash('Error loading messages')
    
    return render_template('chat.html', messages=messages)

@main.route('/delete_message/<message_id>', methods=['POST'])
@login_required
def delete_message(message_id):
    try:
        db = current_app.config['FIREBASE_DB']
        db.child('messages').child(message_id).remove()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@main.route('/logout')
@login_required
def logout():
    # Clear session and cookies
    session.clear()
    response = redirect(url_for('main.login'))
    response.delete_cookie('session')
    return response
