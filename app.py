from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
import os
import json
import hashlib
import secrets
from datetime import datetime, timedelta
import pytz
import asyncio
import aiohttp
from functools import wraps
from werkzeug.middleware.proxy_fix import ProxyFix
import logging

# Configure logging
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

    def generate_key(self) -> str:
        key = secrets.token_hex(8)
        timestamp = datetime.now(self.ph_tz).strftime('%Y%m%d%H%M%S')
        full_key = f"{key}-{timestamp}"
        
        expiry = (datetime.now(self.ph_tz) + timedelta(days=3)).strftime('%Y-%m-%d %H:%M:%S')
        self.keys[full_key] = {
            'expiry': expiry,
            'active': False,
            'created_at': datetime.now(self.ph_tz).strftime('%Y-%m-%d %H:%M:%S'),
            'shares_completed': 0,
            'last_used': None
        }
        self._save_keys()
        return full_key

    def validate_key(self, key: str) -> tuple[bool, str]:
        if key not in self.keys:
            return False, "Invalid key"
        
        key_data = self.keys[key]
        now = datetime.now(self.ph_tz)
        
        if not key_data['active']:
            return False, "Key not approved by admin"
            
        expiry = datetime.strptime(key_data['expiry'], '%Y-%m-%d %H:%M:%S')
        expiry = self.ph_tz.localize(expiry)
        
        if now > expiry:
            return False, "Key has expired"
            
        return True, "Key is valid"

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
            self._save_keys()

    def get_all_keys(self):
        return self.keys

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_logged_in'):
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

async def share_post(token: str, post_id: str):
    headers = {
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36',
        'sec-ch-ua': '"Google Chrome";v="107", "Chromium";v="107", "Not=A?Brand";v="24"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': "Windows",
        'sec-fetch-dest': 'document',
        'sec-fetch-mode': 'navigate',
        'sec-fetch-site': 'none',
        'sec-fetch-user': '?1',
        'upgrade-insecure-requests': '1',
        'accept-encoding': 'gzip, deflate',
        'host': 'graph.facebook.com'
    }
    
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
                ShareStats.update(success=False)
                return False, data.get('error', {}).get('message', 'Unknown error')
        except Exception as e:
            ShareStats.update(success=False)
            return False, str(e)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/generate_key', methods=['POST'])
def generate_key():
    key_manager = KeyManager()
    new_key = key_manager.generate_key()
    return jsonify({'key': new_key})

@app.route('/validate_key', methods=['POST'])
def validate_key():
    key = request.form.get('key')
    key_manager = KeyManager()
    is_valid, message = key_manager.validate_key(key)
    if is_valid:
        session['key'] = key
        return jsonify({'status': 'success', 'message': message})
    return jsonify({'status': 'error', 'message': message})

@app.route('/admin')
@admin_required
def admin():
    key_manager = KeyManager()
    keys = key_manager.get_all_keys()
    
    # Load tokens
    try:
        with open(TOKEN_FILE, 'r') as f:
            tokens = f.read()
    except:
        tokens = ""
    
    # Load stats
    stats = ShareStats.load()
    
    return render_template('admin.html', 
        keys=keys, 
        tokens=tokens, 
        stats=stats,
        active_keys=sum(1 for k in keys.values() if k['active']),
        pending_keys=sum(1 for k in keys.values() if not k['active'])
    )

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
    try:
        with open(TOKEN_FILE, 'w') as f:
            f.write(tokens)
        flash('Tokens updated successfully')
    except Exception as e:
        flash(f'Failed to update tokens: {str(e)}')
    return redirect(url_for('admin'))

@app.route('/share', methods=['POST'])
def share():
    if 'key' not in session:
        return jsonify({'status': 'error', 'message': 'Please validate your key first'})
        
    key_manager = KeyManager()
    is_valid, message = key_manager.validate_key(session['key'])
    if not is_valid:
        return jsonify({'status': 'error', 'message': message})
    
    post_id = request.form.get('post_id')
    share_count = int(request.form.get('share_count', 1))
    
    if not post_id.isdigit():
        return jsonify({'status': 'error', 'message': 'Invalid post ID'})
        
    if not 0 < share_count <= 1000:
        return jsonify({'status': 'error', 'message': 'Share count must be between 1 and 1000'})
    
    try:
        with open(TOKEN_FILE, 'r') as f:
            tokens = [line.strip() for line in f if line.strip()]
            
        if not tokens:
            return jsonify({'status': 'error', 'message': 'No tokens available'})
        
        success = 0
        errors = 0
        
        for token in tokens[:share_count]:
            result, message = asyncio.run(share_post(token, post_id))
            if result:
                success += 1
            else:
                errors += 1
        
        # Update key stats
        key_manager.update_key_stats(session['key'], success)
        
        return jsonify({
            'status': 'success',
            'message': f'Shares completed. Success: {success}, Failed: {errors}'
        })
        
    except Exception as e:
        logger.error(f"Share error: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)})

@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('500.html'), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
