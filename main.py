import os
import uuid
import pyotp
import secrets
from datetime import datetime, timedelta, timezone
from flask import Flask, render_template, request, jsonify, make_response, redirect, abort
from flask_socketio import SocketIO, emit
from jose import jwt
from flask import send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import os
import mimetypes
import tempfile
from PIL import Image
from pillow_heif import register_heif_opener
import base64

app = Flask(__name__)
socketio = SocketIO(app, async_mode="eventlet")

load_dotenv()
# Configuration
UPLOAD_FOLDER = os.getenv("UPLOAD_FOLDER")
TOTP_SECRET = os.getenv("TOTP_KEY")
SECRET_KEY = os.urandom(24)
TOTP_ISSUER = 'FileShareApp'

# Ensure upload directory exists
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SECRET_KEY'] = SECRET_KEY

# Global dictionary to store share links
SHARE_LINKS = {}


# Authentication Middleware
def validate_token(token):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        # Check if token is expired
        if payload['exp'] < datetime.now(timezone.utc).timestamp():
            return False
        return True
    except Exception:
        return False


def create_auth_token(user_id):
    expiration = datetime.now(timezone.utc) + timedelta(minutes=60)
    payload = {
        'sub': user_id,
        'exp': expiration,
        'iat': datetime.now(timezone.utc).timestamp()
    }
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

@app.route('/')
def index():
    return render_template('totp.html')

@app.route('/login', methods=['POST'])
def login():
    user_totp = request.form.get('totp')
    totp = pyotp.TOTP(TOTP_SECRET)

    if totp.verify(user_totp, valid_window=1):
        user_id = str(uuid.uuid4())
        token = create_auth_token(user_id)

        response = make_response(redirect('/upload'))
        response.set_cookie('auth_token', token,
                            httponly=True,
                            secure=True,
                            max_age=3600)  # 1 hour
        return response
    else:
        return render_template('error.html',
                               # error_code=401,
                               error_title='Invalid TOTP',
                               error_message='Invalid TOTP Code, please try again.',
                               # debug_info=str(error),
                               # action_link='/login',
                               # action_text='Try Again'
                               ), 500


@app.route('/upload')
def upload_form():
    token = request.cookies.get('auth_token')
    if not token or not validate_token(token):
        return redirect('/')
    return render_template('upload4.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    token = request.cookies.get('auth_token')
    if not token or not validate_token(token):
        return jsonify({'message': 'Unauthorized'}), 401

    if 'files' not in request.files:
        return jsonify({'message': 'No files part'}), 400

    files = request.files.getlist('files')
    saved_files = []

    for file in files:
        if file.filename == '':
            continue
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(file_path)
        saved_files.append(file.filename)
        notify_file_upload(file.filename)

    if saved_files:
        return jsonify({'message': f"Uploaded files: {', '.join(saved_files)}"}), 200
    else:
        return jsonify({'message': 'No files were uploaded.'}), 400

# New route for creating and managing share links
@app.route('/api/share-link', methods=['POST'])
def create_share_link():
    token = request.cookies.get('auth_token')
    if not token or not validate_token(token):
        return abort(401)

    data = request.json
    filename = data.get('filename')
    password = data.get('password')

    if not filename or filename not in os.listdir(UPLOAD_FOLDER):
        return jsonify({'error': 'File not found'}), 404

    # Check if share link already exists for this file
    for link, details in SHARE_LINKS.items():
        if details['filename'] == filename:
            # If link exists, revoke it
            del SHARE_LINKS[link]
            return jsonify({'message': 'Share link revoked', 'link': None}), 200

    # Create new share link
    share_link = secrets.token_urlsafe(16)

    # Hash password if provided
    hashed_password = generate_password_hash(password) if password else None

    # Store share link details
    SHARE_LINKS[share_link] = {
        'filename': filename,
        'password': hashed_password,
        'created_at': datetime.utcnow()
    }

    print("Create shared password: " + str(SHARE_LINKS[share_link]))

    return jsonify({
        'message': 'Share link created',
        'link': f'/shared/{share_link}',
        'is_password_protected': bool(password)
    }), 200


# New route for accessing shared files
@app.route('/shared/<share_link>', methods=['GET', 'POST'])
def access_shared_file(share_link):
    # Check if share link exists
    if share_link not in SHARE_LINKS:
        return render_template('error.html',
                        error_code=404,
                        error_title='Invalid share link',
                        error_message='Resource not found, expired share link or the link might be taken down.',
                        # debug_info=str(error),
                        action_link='/shared/' + share_link,
                        action_text='Try Again'
                        ), 500

    share_details = SHARE_LINKS[share_link]

    # If password is set, require authentication
    if share_details['password']:
        if request.method == 'GET':
            return render_template('share_password.html', link=share_link)

        # POST method for password verification
        user_totp = request.form.get('totp')
        user_password = request.form.get('password')

        # Verify password or TOTP
        totp = pyotp.TOTP(TOTP_SECRET)
        if (user_password and check_password_hash(share_details['password'], user_password)) or \
                (user_totp and totp.verify(user_totp)):
            filename = share_details['filename']
            return send_from_directory(UPLOAD_FOLDER, filename, as_attachment=True)
        else:
            return "Invalid credentials", 401

    # No password, directly download
    filename = share_details['filename']
    return send_from_directory(UPLOAD_FOLDER, filename, as_attachment=True)


# Modify existing file list API to include share link status
@app.route('/api/files', methods=['GET'])
def get_file_list():
    token = request.cookies.get('auth_token')
    if not token or not validate_token(token):
        return abort(401)

    try:
        files = os.listdir(UPLOAD_FOLDER)
        files_with_details = []
        for file in files:
            file_details = {
                'name': file,
                'size': os.path.getsize(os.path.join(UPLOAD_FOLDER, file)),
                'modified': os.path.getmtime(os.path.join(UPLOAD_FOLDER, file)),
                'share_link': None
            }

            # Check if file has an existing share link
            for link, details in SHARE_LINKS.items():
                if details['filename'] == file:
                    file_details['share_link'] = f'/shared/{link}'
                    break

            files_with_details.append(file_details)

        files_with_details.sort(key=lambda x: x['modified'], reverse=True)
        return jsonify(files_with_details)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# Rest of the code remains the same...

@app.route('/api/files/<filename>', methods=['DELETE'])
def delete_file(filename):
    token = request.cookies.get('auth_token')
    if not token or not validate_token(token):
        return abort(401)

    try:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        if os.path.exists(file_path):
            os.remove(file_path)
            socketio.emit('file_deleted', {'filename': filename})
            return jsonify({'message': f'File {filename} deleted successfully'}), 200
        else:
            return jsonify({'error': 'File not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/uploads/<filename>')
def download_file(filename):
    token = request.cookies.get('auth_token')
    if not token or not validate_token(token):
        return abort(401)

    try:
        return send_from_directory(UPLOAD_FOLDER, filename, as_attachment=True)
    except FileNotFoundError:
        return jsonify({'error': 'File not found'}), 404

def notify_file_upload(filename):
    file_path = os.path.join(UPLOAD_FOLDER, filename)
    file_data = {
        'name': filename,
        'size': os.path.getsize(file_path),
        'modified': os.path.getmtime(file_path)
    }
    socketio.emit('file_uploaded', file_data)


@app.route('/preview/<filename>')
def preview_file(filename: str):
    token = request.cookies.get('auth_token')
    if not token or not validate_token(token):
        return abort(401)

    try:
        file_path = os.path.join(UPLOAD_FOLDER, filename)

        # Check if file exists
        if not os.path.exists(file_path):
            return render_template('error.html',
                                   error_code=404,
                                   error_title='File Not Found',
                                   error_message='The requested file could not be found.',
                                   action_link='/upload',
                                   action_text='Back to Upload'), 404

        # Determine file type
        mime_type, _ = mimetypes.guess_type(file_path)

        # Image preview (including HEIC)
        if mime_type and mime_type.startswith('image/'):
            if mime_type == 'image/heic':
                # Convert HEIC to JPEG
                try:
                    register_heif_opener()
                    image = Image.open(os.path.join(UPLOAD_FOLDER, filename))
                    # image = Image.frombytes(heif_file.mode, heif_file.size, heif_file.data, "raw", heif_file.stride)

                    # Save converted file to a temp folder
                    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.jpg')
                    image.save(temp_file.name, format="JPEG")
                    temp_filename = os.path.basename(temp_file.name)
                    print(temp_filename)
                    os.unlink(temp_file.name)
                    return render_template('file_preview.html',
                                           filename=temp_filename,
                                           base64=image_to_base64(temp_file.name),
                                           file_type='image/heic')
                except Exception as e:
                    return render_template('error.html',
                                           error_code=500,
                                           error_title='HEIC Conversion Error',
                                           error_message='Failed to convert HEIC to JPEG.',
                                           debug_info=str(e),
                                           action_link='/upload',
                                           action_text='Back to Upload'), 500
            else:
                # For other images
                return render_template('file_preview.html',
                                       filename=filename,
                                       file_type='image')

        # Video preview
        elif mime_type and mime_type.startswith('video/'):
            return render_template('file_preview.html',
                                   filename=filename,
                                   file_type='video')

        # Text file preview (limited to certain text types)
        elif mime_type and (mime_type.startswith('text/') or
                            mime_type in ['application/json',
                                          'application/xml',
                                          'text/csv']):
            try:
                with open(file_path, 'r', encoding='utf-8') as file:
                    # Limit preview to first 1000 characters
                    content = file.read(1000)
                    return render_template('file_preview.html',
                                           filename=filename,
                                           file_type='text',
                                           content=content)
            except UnicodeDecodeError:
                return render_template('file_preview.html',
                                       filename=filename,
                                       file_type='binary')

        # For other file types, offer download
        else:
            return render_template('file_preview.html',
                                   filename=filename,
                                   file_type='other')

    except Exception as e:
        return render_template('error.html',
                               error_code=500,
                               error_title='Preview Error',
                               error_message='Unable to preview the file.',
                               debug_info=str(e),
                               action_link='/upload',
                               action_text='Back to Upload'), 500


def image_to_base64(image_path):
    """
    Convert an image to a Base64 string for use in a browser.

    :param image_path: Path to the image file.
    :return: Base64 string (suitable for <img> tags).
    """
    try:
        with open(image_path, "rb") as image_file:
            # Read the image file as binary
            image_data = image_file.read()
            # Encode binary data to Base64
            base64_encoded = base64.b64encode(image_data).decode("utf-8")
            # Get the file extension for the MIME type
            ext = image_path.split('.')[-1]
            return f"data:image/{ext};base64,{base64_encoded}"
    except Exception as e:
        print(f"Error: {e}")
        return None

@app.errorhandler(404)
def not_found_error(error):
    return render_template('error.html',
                           error_code=404,
                           error_title='Page Not Found',
                           error_message='Sorry, the page you are looking for does not exist.',
                           action_link='/',
                           action_text='Go to Login'), 404

@app.errorhandler(401)
def unauthorized_error(error):
    return render_template('error.html',
                           error_code=401,
                           error_title='Unauthorized',
                           error_message='You are not authorized to access this page. Please log in.',
                           action_link='/',
                           action_text='Login'), 401

@app.errorhandler(500)
def internal_error(error):
    return render_template('error.html',
                           error_code=500,
                           error_title='Internal Server Error',
                           error_message='Something went wrong on our end. Please try again later.',
                           debug_info=str(error),
                           action_link='/',
                           action_text='Go to Home'), 500

if __name__ == '__main__':
    print(f'Server started at {datetime.now()}')
    socketio.run(app, host='0.0.0.0', port=5000, allow_unsafe_werkzeug=True)
    # socketio.run(app, host='0.0.0.0', port=5000, debug=False)