from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
import os
import json
import hashlib
import secrets
from datetime import datetime, timedelta
import pytz
import asyncio
import aiohttp
import uuid
import random
from functools import wraps
from werkzeug.middleware.proxy_fix import ProxyFix
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(16))

# Add template context processor for datetime
@app.context_processor
def inject_now():
    return {'now': datetime.utcnow}

# Constants
KEYS_FILE = 'auth_keys.json'
ADMIN_HASH = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"  # Default: "password"
TOKEN_FILE = 'tokens.txt'
SHARE_STATS_FILE = 'share_stats.json'
MAX_TOKENS = 1000

# Role configurations
ROLE_CONFIGS = {
    "free": {
        "share_limit": 250,
        "cooldown": 60,  # seconds
        "description": "Free Plan"
    },
    "premium": {
        "share_limit": None,  # No limit
        "cooldown": 0,  # No cooldown
        "description": "Premium Plan"
    }
}

# Initialize storage
def initialize_files():
    if not os.path.exists(KEYS_FILE):
        with open(KEYS_FILE, 'w') as f:
            json.dump({}, f)

    if not os.path.exists(TOKEN_FILE):
        with open(TOKEN_FILE, 'w') as f:
            f.write('')
            
    if not os.path.exists(SHARE_STATS_FILE):
        with open(SHARE_STATS_FILE, 'w') as f:
            json.dump({'total_shares': 0, 'successful_shares': 0, 'failed_shares': 0}, f)

initialize_files()

# Stats management
class ShareStats:
    @staticmethod
    def load():
        try:
            with open(SHARE_STATS_FILE, 'r') as f:
                return json.load(f)
        except:
            return {'total_shares': 0, 'successful_shares': 0, 'failed_shares': 0}

    @staticmethod
    def update(success=True):
        stats = ShareStats.load()
        stats['total_shares'] += 1
        if success:
            stats['successful_shares'] += 1
        else:
            stats['failed_shares'] += 1
        
        with open(SHARE_STATS_FILE, 'w') as f:
            json.dump(stats, f)

# Key management
class KeyManager:
    def __init__(self, keys_file=KEYS_FILE):
        self.keys_file = keys_file
        self.keys = self._load_keys()
        self.ph_tz = pytz.timezone('Asia/Manila')

    def _load_keys(self):
        if os.path.exists(self.keys_file):
            try:
                with open(self.keys_file, 'r') as f:
                    return json.load(f)
            except:
                return {}
        return {}

    def _save_keys(self):
        with open(self.keys_file, 'w') as f:
            json.dump(self.keys, f, indent=4)

    def generate_key(self, role="free") -> str:
        key = secrets.token_hex(8)
        timestamp = datetime.now(self.ph_tz).strftime('%Y%m%d%H%M%S')
        full_key = f"{key}-{timestamp}"
        
        self.keys[full_key] = {
            'expiry': "permanent",
            'active': False,
            'role': role,
            'created_at': datetime.now(self.ph_tz).strftime('%Y-%m-%d %H:%M:%S'),
            'shares_completed': 0,
            'last_used': None,
            'last_share': None
        }
        self._save_keys()
        return full_key

    def validate_key(self, key: str) -> tuple[bool, str]:
        if key not in self.keys:
            return False, "Invalid key"
        
        key_data = self.keys[key]
        
        if not key_data['active']:
            return False, "Key not approved by admin"
            
        return True, "Key is valid"

    def can_share(self, key: str, share_count: int) -> tuple[bool, str]:
        if key not in self.keys:
            return False, "Invalid key"

        key_data = self.keys[key]
        now = datetime.now(self.ph_tz)
        role_config = ROLE_CONFIGS[key_data['role']]

        # Check share limit
        if role_config['share_limit'] and share_count > role_config['share_limit']:
            return False, f"Share count exceeds plan limit ({role_config['share_limit']})"

        # Check cooldown
        if role_config['cooldown'] > 0 and key_data['last_share']:
            last_share_time = datetime.strptime(key_data['last_share'], '%Y-%m-%d %H:%M:%S')
            last_share_time = self.ph_tz.localize(last_share_time)
            cooldown_end = last_share_time + timedelta(seconds=role_config['cooldown'])
            
            if now < cooldown_end:
                remaining = int((cooldown_end - now).total_seconds())
                return False, f"Please wait {remaining} seconds before sharing again"

        return True, "Allowed to share"

    def approve_key(self, key: str) -> bool:
        if key in self.keys and not self.keys[key]['active']:
            self.keys[key]['active'] = True
            self._save_keys()
            return True
        return False

    def revoke_key(self, key: str) -> bool:
        if key in self.keys:
            self.keys[key]['active'] = False
            self._save_keys()
            return True
        return False

    def delete_key(self, key: str) -> bool:
        if key in self.keys:
            del self.keys[key]
            self._save_keys()
            return True
        return False

    def update_key_stats(self, key: str, shares_completed: int):
        if key in self.keys:
            self.keys[key]['shares_completed'] += shares_completed
            self.keys[key]['last_used'] = datetime.now(self.ph_tz).strftime('%Y-%m-%d %H:%M:%S')
            self.keys[key]['last_share'] = datetime.now(self.ph_tz).strftime('%Y-%m-%d %H:%M:%S')
            self._save_keys()

    def get_key_info(self, key: str) -> dict:
        if key in self.keys:
            key_data = self.keys[key]
            role_config = ROLE_CONFIGS[key_data['role']]
            
            return {
                'role': key_data['role'],
                'role_name': role_config['description'],
                'share_limit': role_config['share_limit'] or "Unlimited",
                'cooldown': role_config['cooldown'],
                'shares_completed': key_data['shares_completed'],
                'last_used': key_data['last_used'],
                'created_at': key_data['created_at'],
                'last_share': key_data['last_share']
            }
        return None

    def get_all_keys(self):
        return self.keys

# Authentication decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_logged_in'):
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

# API Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/get_key_info', methods=['GET'])
def get_key_info():
    if 'key' not in session:
        return jsonify({'status': 'error', 'message': 'No active key'})
    
    key_manager = KeyManager()
    key_info = key_manager.get_key_info(session['key'])
    
    if key_info:
        return jsonify({
            'status': 'success',
            'key_info': key_info
        })
    return jsonify({'status': 'error', 'message': 'Invalid key'})

@app.route('/generate_key', methods=['POST'])
def generate_key():
    key_manager = KeyManager()
    role = request.form.get('role', 'free')
    if role not in ROLE_CONFIGS:
        role = 'free'
    new_key = key_manager.generate_key(role)
    return jsonify({'key': new_key})

@app.route('/validate_key', methods=['POST'])
def validate_key():
    key = request.form.get('key')
    remember = request.form.get('remember', 'false') == 'true'
    key_manager = KeyManager()
    is_valid, message = key_manager.validate_key(key)
    if is_valid:
        session['key'] = key
        if remember:
            session.permanent = True
            app.permanent_session_lifetime = timedelta(days=30)
        key_info = key_manager.get_key_info(key)
        return jsonify({
            'status': 'success',
            'message': message,
            'key_info': key_info
        })
    return jsonify({'status': 'error', 'message': message})

@app.route('/check_session', methods=['GET'])
def check_session():
    if 'key' in session:
        key_manager = KeyManager()
        is_valid, message = key_manager.validate_key(session['key'])
        if is_valid:
            key_info = key_manager.get_key_info(session['key'])
            return jsonify({
                'status': 'success',
                'key': session['key'],
                'key_info': key_info
            })
    return jsonify({'status': 'error'})

@app.route('/logout', methods=['POST'])
def logout():
    session.pop('key', None)
    return jsonify({'status': 'success'})

# Admin routes remain the same...

@app.route('/share', methods=['POST'])
def share():
    if 'key' not in session:
        return jsonify({'status': 'error', 'message': 'Please validate your key first'})
        
    key_manager = KeyManager()
    key = session['key']
    post_id = request.form.get('post_id')
    share_count = int(request.form.get('share_count', 1))
    
    # Validate sharing permissions
    can_share, message = key_manager.can_share(key, share_count)
    if not can_share:
        return jsonify({'status': 'error', 'message': message})
    
    if not post_id.isdigit():
        return jsonify({'status': 'error', 'message': 'Invalid post ID'})
    
    try:
        with open(TOKEN_FILE, 'r') as f:
            tokens = [line.strip() for line in f if line.strip()]
            
        if not tokens:
            return jsonify({'status': 'error', 'message': 'No tokens available'})
        
        actual_share_count = min(share_count, len(tokens))
        
        success = 0
        errors = 0
        valid_tokens = []
        invalid_tokens = []
        
        async def process_tokens():
            nonlocal success, errors
            
            async with aiohttp.ClientSession() as session:
                tasks = []
                for token in tokens[:actual_share_count]:
                    task = asyncio.create_task(share_post(token, post_id))
                    tasks.append((token, task))
                
                for token, task in tasks:
                    try:
                        result, message = await task
                        if result:
                            success += 1
                            valid_tokens.append(token)
                        else:
                            errors += 1
                            if "expired" in message.lower() or "invalid" in message.lower():
                                invalid_tokens.append(token)
                            else:
                                valid_tokens.append(token)
                    except Exception as e:
                        errors += 1
                        logger.error(f"Error with token {token}: {str(e)}")
                        if "expired" in str(e).lower() or "invalid" in str(e).lower():
                            invalid_tokens.append(token)
                        else:
                            valid_tokens.append(token)
        
        asyncio.run(process_tokens())
        
        all_tokens = valid_tokens + tokens[actual_share_count:]
        with open(TOKEN_FILE, 'w') as f:
            f.write('\n'.join(all_tokens))
            
        key_manager.update_key_stats(key, success)
        
        key_info = key_manager.get_key_info(key)
        removed_count = len(invalid_tokens)
        
        return jsonify({
            'status': 'success',
            'message': f'Shares completed. Success: {success}, Failed: {errors}, Invalid tokens removed: {removed_count}, Available tokens: {len(all_tokens)}',
            'key_info': key_info,
            'available_tokens': len(all_tokens),
            'success_count': success,
            'updated_max_shares': len(all_tokens)
        })
            
    except Exception as e:
        logger.error(f"Share error: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)})

# Share post function
async def share_post(token: str, post_id: str):
    headers = {
        'user-agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36',
        'sec-ch-ua': '"Not_A Brand";v="8", "Chromium";v="120"',
        'sec-ch-ua-mobile': '?1',
        'sec-ch-ua-platform': "Android",
        'sec-fetch-dest': 'document',
        'sec-fetch-mode': 'navigate',
        'sec-fetch-site': 'none',
        'sec-fetch-user': '?1',
        'upgrade-insecure-requests': '1',
        'accept-encoding': 'gzip, deflate',
        'host': 'graph.facebook.com'
    }
    
    try:
        async with aiohttp.ClientSession() as session:
            try:
                async with session.post(
                    'https://graph.facebook.com/me/feed',
                    params={
                        'link': f'https://facebook.com/{post_id}',
                        'published': '0',
                        'access_token': token
                    },
                    headers=headers,
                    timeout=30
                ) as response:
                    data = await response.json()
                    
                    if 'id' in data:
                        ShareStats.update(success=True)
                        return True, "Share successful"
                    
                    error = data.get('error', {})
                    error_code = error.get('code')
                    error_message = error.get('message', 'Unknown error')
                    
                    if error_code in [190, 463, 467]:  # Invalid/Expired token errors
                        raise Exception(f"Token invalid or expired: {error_message}")
                    elif error_code == 4:  # Rate limit
                        raise Exception(f"Rate limited: {error_message}")
                    elif error_code == 506:  # Duplicate post
                        raise Exception(f"Duplicate post: {error_message}")
                    
                    ShareStats.update(success=False)
                    return False, error_message
                    
            except aiohttp.ClientError as e:
                raise Exception(f"Network error: {str(e)}")
            except asyncio.TimeoutError:
                raise Exception("Request timed out")
                
    except Exception as e:
        ShareStats.update(success=False)
        return False, str(e)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
