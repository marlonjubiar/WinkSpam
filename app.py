from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
import os
import json
import hashlib
import secrets
import asyncio
import aiohttp
import pytz
import logging
from datetime import datetime, timedelta
from functools import wraps
from werkzeug.middleware.proxy_fix import ProxyFix
import concurrent.futures

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(16))
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max-limit

# Constants
KEYS_FILE = 'auth_keys.json'
ADMIN_HASH = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"  # Default: "password"
TOKEN_FILE = 'tokens.txt'
SHARE_STATS_FILE = 'share_stats.json'
MAX_SHARES_PER_REQUEST = 1000
RATE_LIMIT_WINDOW = 3600  # 1 hour
MAX_SHARES_PER_HOUR = 5000

class RateLimiter:
    def __init__(self):
        self.requests = {}
        self.window = RATE_LIMIT_WINDOW
        self.limit = MAX_SHARES_PER_HOUR

    def is_rate_limited(self, key: str, shares: int) -> bool:
        now = datetime.now().timestamp()
        if key not in self.requests:
            self.requests[key] = []

        # Clean old requests
        self.requests[key] = [ts for ts in self.requests[key] 
                            if now - ts < self.window]

        # Check if adding new shares would exceed limit
        total_shares = len(self.requests[key]) + shares
        if total_shares > self.limit:
            return True

        # Add new shares
        self.requests[key].extend([now] * shares)
        return False

rate_limiter = RateLimiter()

def initialize_files():
    """Initialize necessary files if they don't exist"""
    files = {
        KEYS_FILE: '{}',
        TOKEN_FILE: '',
        SHARE_STATS_FILE: '{"total_shares": 0, "successful_shares": 0, "failed_shares": 0}'
    }
    
    for file_path, default_content in files.items():
        if not os.path.exists(file_path):
            with open(file_path, 'w') as f:
                f.write(default_content)
            logger.info(f"Created file: {file_path}")

initialize_files()

class ShareStats:
    @staticmethod
    def load():
        try:
            with open(SHARE_STATS_FILE, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error loading share stats: {str(e)}")
            return {'total_shares': 0, 'successful_shares': 0, 'failed_shares': 0}

    @staticmethod
    def update(success=True):
        try:
            stats = ShareStats.load()
            stats['total_shares'] += 1
            if success:
                stats['successful_shares'] += 1
            else:
                stats['failed_shares'] += 1
            
            with open(SHARE_STATS_FILE, 'w') as f:
                json.dump(stats, f)
        except Exception as e:
            logger.error(f"Error updating share stats: {str(e)}")

class KeyManager:
    def __init__(self, keys_file=KEYS_FILE):
        self.keys_file = keys_file
        self.keys = self._load_keys()
        self.ph_tz = pytz.timezone('Asia/Manila')

    def _load_keys(self):
        try:
            if os.path.exists(self.keys_file):
                with open(self.keys_file, 'r') as f:
                    return json.load(f)
            return {}
        except Exception as e:
            logger.error(f"Error loading keys: {str(e)}")
            return {}

    def _save_keys(self):
        try:
            with open(self.keys_file, 'w') as f:
                json.dump(self.keys, f, indent=4)
        except Exception as e:
            logger.error(f"Error saving keys: {str(e)}")

    def generate_key(self) -> str:
        try:
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
        except Exception as e:
            logger.error(f"Error generating key: {str(e)}")
            return None

    def validate_key(self, key: str) -> tuple[bool, str]:
        try:
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
        except Exception as e:
            logger.error(f"Error validating key: {str(e)}")
            return False, "Error validating key"

    def handle_key_action(self, key: str, action: str) -> bool:
        try:
            if key not in self.keys:
                return False
                
            if action == 'approve':
                self.keys[key]['active'] = True
            elif action == 'revoke':
                self.keys[key]['active'] = False
            elif action == 'delete':
                del self.keys[key]
            else:
                return False
                
            self._save_keys()
            return True
        except Exception as e:
            logger.error(f"Error handling key action: {str(e)}")
            return False

    def update_key_stats(self, key: str, shares_completed: int):
        try:
            if key in self.keys:
                self.keys[key]['shares_completed'] += shares_completed
                self.keys[key]['last_used'] = datetime.now(self.ph_tz).strftime('%Y-%m-%d %H:%M:%S')
                self._save_keys()
        except Exception as e:
            logger.error(f"Error updating key stats: {str(e)}")

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_logged_in'):
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

async def share_post(token: str, post_id: str) -> tuple[bool, str]:
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
    
    try:
        async with aiohttp.ClientSession() as session:
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
        logger.error(f"Share error: {str(e)}")
        ShareStats.update(success=False)
        return False, str(e)

async def process_shares(tokens: list, post_id: str, share_count: int) -> tuple[int, int]:
    success = 0
    errors = 0
    
    tasks = []
    for token in tokens[:share_count]:
        tasks.append(share_post(token, post_id))
    
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    for result in results:
        if isinstance(result, tuple) and result[0]:
            success += 1
        else:
            errors += 1
            
    return success, errors

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/generate_key', methods=['POST'])
def generate_key():
    key_manager = KeyManager()
    new_key = key_manager.generate_key()
    if new_key:
        return jsonify({'key': new_key})
    return jsonify({'status': 'error', 'message': 'Failed to generate key'})

@app.route('/validate_key', methods=['POST'])
def validate_key():
    key = request.form.get('key')
    if not key:
        return jsonify({'status': 'error', 'message': 'No key provided'})
        
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
    keys = key_manager.keys
    
    try:
        with open(TOKEN_FILE, 'r') as f:
            tokens = f.read()
    except Exception as e:
        logger.error(f"Error reading tokens: {str(e)}")
        tokens = ""
    
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
        password = request.form.get('password', '')
        if hashlib.sha256(password.encode()).hexdigest() == ADMIN_HASH:
            session['admin_logged_in'] = True
            return redirect(url_for('admin'))
        flash('Invalid password')
    return render_template('admin_login.html')

@app.route('/admin/approve_key/<key>')
@admin_required
def approve_key(key):
    key_manager = KeyManager()
    if key_manager.handle_key_action(key, 'approve'):
        flash('Key approved successfully')
    else:
        flash('Failed to approve key')
    return redirect(url_for('admin'))

@app.route('/admin/revoke_key/<key>')
@admin_required
def revoke_key(key):
    key_manager = KeyManager()
    if key_manager.handle_key_action(key, 'revoke'):
        flash('Key revoked successfully')
    else:
        flash('Failed to revoke key')
    return redirect(url_for('admin'))

@app.route('/admin/delete_key/<key>')
@admin_required
def delete_key(key):
    key_manager = KeyManager()
    if key_manager.handle_key_action(key, 'delete'):
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
        logger.error(f"Error updating tokens: {str(e)}")
        flash(f'Failed to update tokens: {str(e)}')
    return redirect(url_for('admin'))

@app.route('/share', methods=['POST'])
async def share():
    if 'key' not in session:
        return jsonify({'status': 'error', 'message': 'Please validate your key first'})
        
    key_manager = KeyManager()
    is_valid, message = key_manager.validate_key(session['key'])
    if not is_valid:
        return jsonify({'status': 'error', 'message': message})
    
    try:
        post_id = request.form.get('post_id', '')
        share_count = int(request.form.get('share_count', 0))
        
        if not post_id.isdigit():
            return jsonify({'status': 'error', 'message': 'Invalid post ID'})
            
        if not 0 < share_count <= MAX_SHARES_PER_REQUEST:
            return jsonify({'status': 'error', 
                          'message': f'Share count must be between 1 and {MAX_SHARES_PER_REQUEST}'})
        
        # Check rate limit
        if rate_limiter.is_rate_limited(session['key'], share_count):
            return jsonify({'status': 'error', 
                          'message': f'Rate limit exceeded. Maximum {MAX_SHARES_PER_HOUR} shares per hour.'})
        
        # Load tokens
        try:
            with open(TOKEN_FILE, 'r') as f:
                tokens = [line.strip() for line in f if line.strip()]
                
            if not tokens:
                return jsonify({'status': 'error', 'message': 'No tokens available'})
            
            loop = asyncio.get_event_loop()
            success, errors = await process_shares(tokens, post_id, share_count)
            
            # Update key stats
            key_manager.update_key_stats(session['key'], success)
            
            message = (f'Share process completed!\n'
                      f'- Successful: {success}\n'
                      f'- Failed: {errors}')
            
            return jsonify({
                'status': 'success',
                'message': message
            })
            
        except ValueError:
            return jsonify({
                'status': 'error',
                'message': 'Invalid share count'
            })
        except Exception as e:
            logger.error(f"Share error: {str(e)}")
            return jsonify({
                'status': 'error',
                'message': f'Error processing request: {str(e)}'
            })

@app.route('/api/stats')
@admin_required
def get_stats():
    """API endpoint for getting current stats"""
    try:
        stats = ShareStats.load()
        return jsonify({
            'status': 'success',
            'data': stats
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        })

@app.route('/api/keys')
@admin_required
def get_keys():
    """API endpoint for getting key information"""
    try:
        key_manager = KeyManager()
        return jsonify({
            'status': 'success',
            'data': key_manager.keys
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        })

@app.errorhandler(404)
def not_found_error(error):
    """Handle 404 errors"""
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    logger.error(f"Internal server error: {str(error)}")
    return render_template('500.html'), 500

@app.errorhandler(429)
def ratelimit_handler(error):
    """Handle rate limit errors"""
    return jsonify({
        'status': 'error',
        'message': 'Rate limit exceeded. Please try again later.'
    }), 429

def setup_app():
    """Initialize the application"""
    try:
        # Ensure required directories exist
        os.makedirs('logs', exist_ok=True)
        
        # Initialize files
        initialize_files()
        
        # Setup logging to file
        file_handler = logging.FileHandler('logs/app.log')
        file_handler.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        
        logger.info("Application initialized successfully")
    except Exception as e:
        logger.error(f"Error setting up application: {str(e)}")
        raise

if __name__ == '__main__':
    # Initialize the application
    setup_app()
    
    # Get port from environment or use default
    port = int(os.environ.get('PORT', 5000))
    
    # Run the application
    app.run(
        host='0.0.0.0',
        port=port,
        debug=False  # Set to False in production
    )
