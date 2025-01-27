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

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(16))

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
        "cooldown": 60,
        "description": "Free Plan"
    },
    "premium": {
        "share_limit": None,
        "cooldown": 0,
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

class ShareStats:
    @staticmethod
    def update(success=True):
        try:
            with open(SHARE_STATS_FILE, 'r') as f:
                stats = json.load(f)
            stats['total_shares'] += 1
            if success:
                stats['successful_shares'] += 1
            else:
                stats['failed_shares'] += 1
            with open(SHARE_STATS_FILE, 'w') as f:
                json.dump(stats, f)
        except:
            pass

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
        if role not in ROLE_CONFIGS:
            role = "free"
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
            return False, "Key not approved"
        return True, "Key is valid"

    def can_share(self, key: str, share_count: int) -> tuple[bool, str]:
        if key not in self.keys:
            return False, "Invalid key"
        key_data = self.keys[key]
        if not key_data['active']:
            return False, "Key not approved"
        role_config = ROLE_CONFIGS[key_data['role']]
        if role_config['share_limit'] and share_count > role_config['share_limit']:
            return False, f"Share count exceeds limit ({role_config['share_limit']})"
        return True, "Allowed to share"

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

# Authentication decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_logged_in'):
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

async def share_post(token: str, post_id: str, target_shares: int):
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
    
    shares_completed = 0
    async with aiohttp.ClientSession() as session:
        while shares_completed < target_shares:
            try:
                async with session.post(
                    'https://graph.facebook.com/me/feed',
                    params={
                        'link': f'https://facebook.com/{post_id}',
                        'published': '0',
                        'access_token': token
                    },
                    headers=headers,
                    timeout=10
                ) as response:
                    data = await response.json()
                    if 'id' in data:
                        shares_completed += 1
                        ShareStats.update(success=True)
                        continue
                    error = data.get('error', {})
                    error_code = error.get('code')
                    if error_code in [190, 463, 467]:
                        return shares_completed, False
                    if error_code == 4 or error_code == 506:
                        return shares_completed, True
                    return shares_completed, True
            except Exception:
                return shares_completed, True
    return shares_completed, True

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

@app.route('/share', methods=['POST'])
def share():
    if 'key' not in session:
        return jsonify({'status': 'error', 'message': 'Please validate your key first'})
    
    key_manager = KeyManager()
    key = session['key']
    post_id = request.form.get('post_id')
    share_count = int(request.form.get('share_count', 1))
    
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
        
        remaining_shares = share_count
        success = 0
        valid_tokens = []
        
        async def process_share_batch():
            nonlocal remaining_shares, success, valid_tokens
            
            while remaining_shares > 0 and tokens:
                batch_tasks = []
                shares_per_token = max(1, remaining_shares // len(tokens))
                
                for token in tokens[:]:
                    if remaining_shares <= 0:
                        break
                    batch_tasks.append((token, asyncio.create_task(
                        share_post(token, post_id, shares_per_token)
                    )))
                
                for token, task in batch_tasks:
                    try:
                        shares_done, is_valid = await task
                        success += shares_done
                        remaining_shares -= shares_done
                        
                        if is_valid:
                            valid_tokens.append(token)
                            
                    except Exception as e:
                        logger.error(f"Share error: {str(e)}")
                        continue
        
        asyncio.run(process_share_batch())
        
        with open(TOKEN_FILE, 'w') as f:
            f.write('\n'.join(valid_tokens))
        
        key_manager.update_key_stats(key, success)
        
        return jsonify({
            'status': 'success',
            'message': f'Shares completed: {success}',
            'success_count': success,
            'available_tokens': len(valid_tokens)
        })
            
    except Exception as e:
        logger.error(f"Share error: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/get_token_count', methods=['GET'])
def get_token_count():
    try:
        with open(TOKEN_FILE, 'r') as f:
            tokens = [line.strip() for line in f if line.strip()]
        return jsonify({
            'status': 'success',
            'count': len(tokens)
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        })

@app.route('/admin')
@admin_required
def admin():
    try:
        key_manager = KeyManager()
        keys = key_manager.get_all_keys()
        
        with open(TOKEN_FILE, 'r') as f:
            tokens = f.read()
        
        with open(SHARE_STATS_FILE, 'r') as f:
            stats = json.load(f)
        
        active_keys = sum(1 for k in keys.values() if k['active'])
        pending_keys = sum(1 for k in keys.values() if not k['active'])
        current_tokens = len([t for t in tokens.split('\n') if t.strip()])
        
        role_counts = {'premium': 0, 'free': 0}
        for key_data in keys.values():
            if key_data['active']:
                role_counts[key_data['role']] += 1
        
        return render_template('admin.html', 
            keys=keys, 
            tokens=tokens,
            stats=stats,
            active_keys=active_keys,
            pending_keys=pending_keys,
            current_tokens=current_tokens,
            max_tokens=MAX_TOKENS,
            premium_keys=role_counts['premium'],
            free_keys=role_counts['free']
        )
    except Exception as e:
        logger.error(f"Admin page error: {str(e)}")
        flash('An error occurred while loading the admin page.')
        return redirect(url_for('admin_login'))

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        password = request.form.get('password')
        if hashlib.sha256(password.encode()).hexdigest() == ADMIN_HASH:
            session['admin_logged_in'] = True
            return redirect(url_for('admin'))
        flash('Invalid password')
    return render_template('admin_login.html')

@app.route('/admin/approve_key/<key>')
@admin_required
def approve_key(key):
    key_manager = KeyManager()
    if key_manager.approve_key(key):
        flash('Key approved successfully')
    else:
        flash('Failed to approve key')
    return redirect(url_for('admin'))

@app.route('/admin/revoke_key/<key>')
@admin_required
def revoke_key(key):
    key_manager = KeyManager()
    if key_manager.revoke_key(key):
        flash('Key revoked successfully')
    else:
        flash('Failed to revoke key')
    return redirect(url_for('admin'))

@app.route('/admin/delete_key/<key>')
@admin_required
def delete_key(key):
    key_manager = KeyManager()
    if key_manager.delete_key(key):
        flash('Key deleted successfully')
    else:
        flash('Failed to delete key')
    return redirect(url_for('admin'))

@app.route('/admin/tokens', methods=['POST'])
@admin_required
def update_tokens():
    tokens = request.form.get('tokens', '')
    token_list = [t.strip() for t in tokens.split('\n') if t.strip()]
    
    if len(token_list) > MAX_TOKENS:
        flash(f'Maximum {MAX_TOKENS} tokens allowed')
        return redirect(url_for('admin'))
    
    try:
        with open(TOKEN_FILE, 'w') as f:
            f.write('\n'.join(token_list))
        flash(f'Successfully updated {len(token_list)} tokens')
    except Exception as e:
        flash(f'Failed to update tokens: {str(e)}')
    return redirect(url_for('admin'))

@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal server error: {str(error)}")
    return render_template('500.html'), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
