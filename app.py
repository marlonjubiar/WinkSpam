from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
import os
import json
import hashlib
import secrets
from datetime import datetime, timedelta
import pytz
import asyncio
import aiohttp
import logging
from functools import wraps
from werkzeug.middleware.proxy_fix import ProxyFix

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(16))
app.permanent_session_lifetime = timedelta(days=30)

# Constants
KEYS_FILE = 'auth_keys.json'
ADMIN_HASH = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
TOKEN_FILE = 'tokens.txt'
SHARE_STATS_FILE = 'share_stats.json'
BAN_FILE = 'banned_ips.json'
MAX_TOKENS = 1000
MAX_KEY_ATTEMPTS = 3
BAN_DURATION_HOURS = 24

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

def initialize_files():
    files = {
        KEYS_FILE: {},
        TOKEN_FILE: '',
        SHARE_STATS_FILE: {'total_shares': 0, 'successful_shares': 0, 'failed_shares': 0},
        BAN_FILE: {}
    }
    
    for file_path, default_content in files.items():
        if not os.path.exists(file_path):
            with open(file_path, 'w') as f:
                if isinstance(default_content, (dict, list)):
                    json.dump(default_content, f)
                else:
                    f.write(default_content)

initialize_files()

class BanManager:
    @staticmethod
    def check_ban(ip_address: str) -> tuple[bool, str]:
        try:
            with open(BAN_FILE, 'r') as f:
                bans = json.load(f)
            
            if ip_address in bans:
                ban_data = bans[ip_address]
                ban_until = datetime.fromisoformat(ban_data['until'])
                
                if datetime.now() < ban_until:
                    remaining = ban_until - datetime.now()
                    hours = remaining.total_seconds() / 3600
                    return True, f"You are banned for {hours:.1f} more hours"
                else:
                    del bans[ip_address]
                    with open(BAN_FILE, 'w') as f:
                        json.dump(bans, f)
            
            return False, ""
        except:
            return False, ""

    @staticmethod
    def add_attempt(ip_address: str):
        try:
            with open(BAN_FILE, 'r') as f:
                bans = json.load(f)
            
            if ip_address not in bans:
                bans[ip_address] = {
                    'attempts': 1,
                    'until': None
                }
            else:
                if bans[ip_address]['attempts'] < MAX_KEY_ATTEMPTS:
                    bans[ip_address]['attempts'] += 1
                
                if bans[ip_address]['attempts'] >= MAX_KEY_ATTEMPTS:
                    ban_until = datetime.now() + timedelta(hours=BAN_DURATION_HOURS)
                    bans[ip_address]['until'] = ban_until.isoformat()
            
            with open(BAN_FILE, 'w') as f:
                json.dump(bans, f)
                
            return bans[ip_address]['attempts']
        except:
            return 0

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
        except Exception as e:
            logger.error(f"Error updating stats: {str(e)}")

    @staticmethod
    def get_stats():
        try:
            with open(SHARE_STATS_FILE, 'r') as f:
                return json.load(f)
        except:
            return {
                'total_shares': 0,
                'successful_shares': 0,
                'failed_shares': 0
            }

class KeyManager:
    def __init__(self):
        self.keys_file = KEYS_FILE
        self.keys = self._load_keys()
        self.ph_tz = pytz.timezone('Asia/Manila')

    def _load_keys(self):
        try:
            with open(self.keys_file, 'r') as f:
                return json.load(f)
        except:
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
            'role': role,
            'active': False,
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
            
        if role_config['cooldown'] > 0 and key_data.get('last_share'):
            last_share = datetime.strptime(key_data['last_share'], '%Y-%m-%d %H:%M:%S')
            last_share = self.ph_tz.localize(last_share)
            cooldown_end = last_share + timedelta(seconds=role_config['cooldown'])
            
            if datetime.now(self.ph_tz) < cooldown_end:
                remaining = int((cooldown_end - datetime.now(self.ph_tz)).total_seconds())
                return False, f"Please wait {remaining} seconds"
                
        return True, "Allowed to share"

    def update_key_stats(self, key: str, shares_completed: int):
        if key in self.keys:
            self.keys[key]['shares_completed'] += shares_completed
            current_time = datetime.now(self.ph_tz).strftime('%Y-%m-%d %H:%M:%S')
            self.keys[key]['last_used'] = current_time
            self.keys[key]['last_share'] = current_time
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
        for _ in range(target_shares):
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
                    if error_code == 4:
                        return shares_completed, True
            except Exception:
                return shares_completed, True
                
    return shares_completed, True

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/generate_key', methods=['POST'])
def generate_key():
    try:
        # Get IP address
        ip_address = request.remote_addr
        
        # Check if IP is banned
        is_banned, ban_message = BanManager.check_ban(ip_address)
        if is_banned:
            return jsonify({
                'status': 'error',
                'message': ban_message
            })

        key_manager = KeyManager()
        key_type = request.form.get('type', 'free')
        admin_password = request.form.get('admin_password', '')

        if key_type == 'premium':
            if hashlib.sha256(admin_password.encode()).hexdigest() != ADMIN_HASH:
                attempts = BanManager.add_attempt(ip_address)
                remaining_attempts = MAX_KEY_ATTEMPTS - attempts
                
                if remaining_attempts > 0:
                    return jsonify({
                        'status': 'error',
                        'message': f'Invalid admin password. {remaining_attempts} attempts remaining.'
                    })
                else:
                    return jsonify({
                        'status': 'error',
                        'message': f'You have been banned for {BAN_DURATION_HOURS} hours due to too many attempts.'
                    })

        new_key = key_manager.generate_key('premium' if key_type == 'premium' else 'free')
        key_info = {
            'key': new_key,
            'role': 'premium' if key_type == 'premium' else 'free',
            'role_name': ROLE_CONFIGS['premium' if key_type == 'premium' else 'free']['description'],
            'share_limit': ROLE_CONFIGS['premium' if key_type == 'premium' else 'free']['share_limit'] or "Unlimited",
            'cooldown': ROLE_CONFIGS['premium' if key_type == 'premium' else 'free']['cooldown']
        }
        
        return jsonify({
            'status': 'success',
            'message': 'Key generated successfully. Waiting for admin approval.',
            'key_info': key_info
        })
    except Exception as e:
        logger.error(f"Key generation error: {str(e)}")
        return jsonify({'status': 'error', 'message': 'Failed to generate key'})

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
        
        key_info = key_manager.get_key_info(key)
        return jsonify({
            'status': 'success',
            'message': 'Key validated successfully',
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
        
        success = 0
        valid_tokens = []
        
        async def process_share_batch():
            nonlocal success, valid_tokens
            batch_tasks = []
            
            for token in tokens:
                if success >= share_count:
                    break
                task = asyncio.create_task(share_post(token, post_id, 1))
                batch_tasks.append((token, task))
            
            for token, task in batch_tasks:
                try:
                    shares_done, is_valid = await task
                    success += shares_done
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
            'message': f'Successfully completed {success} shares',
            'success_count': success,
            'available_tokens': len(valid_tokens),
            'key_info': key_manager.get_key_info(key)
        })
            
    except Exception as e:
        logger.error(f"Share error: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/quick_share', methods=['POST'])
def quick_share():
    if 'key' not in session:
        return jsonify({'status': 'error', 'message': 'Please validate your key first'})

    key_manager = KeyManager()
    key = session['key']
    post_id = request.form.get('post_id')
    share_count = int(request.form.get('share_count', 50))

    can_share, message = key_manager.can_share(key, share_count)
    if not can_share:
        return jsonify({'status': 'error', 'message': message})

    try:
        with open(TOKEN_FILE, 'r') as f:
            tokens = [line.strip() for line in f if line.strip()]

        if not tokens:
            return jsonify({'status': 'error', 'message': 'No tokens available'})

        success = 0
        valid_tokens = []
        total_shares = min(share_count, len(tokens))

        async def process_quick_share():
            nonlocal success, valid_tokens
            batch_tasks = []
            
            for token in tokens[:total_shares]:
                task = asyncio.create_task(share_post(token, post_id, 1))
                batch_tasks.append((token, task))
            
            for token, task in batch_tasks:
                try:
                    shares_done, is_valid = await task
                    success += shares_done
                    if is_valid:
                        valid_tokens.append(token)
                except Exception as e:
                    logger.error(f"Share error: {str(e)}")
                    continue

        asyncio.run(process_quick_share())

        with open(TOKEN_FILE, 'w') as f:
            f.write('\n'.join(valid_tokens))

        key_manager.update_key_stats(key, success)

        return jsonify({
            'status': 'success',
            'message': f'Quick share completed: {success} shares',
            'success_count': success,
            'available_tokens': len(valid_tokens),
            'key_info': key_manager.get_key_info(key)
        })

    except Exception as e:
        logger.error(f"Quick share error: {str(e)}")
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
            
        active_keys = sum(1 for k in keys.values() if k['active'])
        pending_keys = sum(1 for k in keys.values() if not k['active'])
        current_tokens = len([t for t in tokens.split('\n') if t.strip()])
        
        return render_template('admin.html',
            keys=keys,
            tokens=tokens,
            active_keys=active_keys,
            pending_keys=pending_keys,
            current_tokens=current_tokens,
            max_tokens=MAX_TOKENS
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

@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'status': 'success'})

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

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
