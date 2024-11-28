from flask import Flask, render_template, request, jsonify
import os
from flask_socketio import SocketIO as socketio


app = Flask(__name__)

# Folder to save uploaded files
UPLOAD_FOLDER = 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


@app.route('/')
def upload_form():
    return render_template('upload4.html')


@app.route('/upload', methods=['POST'])
def upload_file():
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

    if saved_files:
        return jsonify({'message': f"Uploaded files: {', '.join(saved_files)}"}), 200
    else:
        return jsonify({'message': 'No files were uploaded.'}), 400

@app.route('/api/files', methods=['GET'])
def get_file_list():
    try:
        # List all files in the upload folder
        files = os.listdir(UPLOAD_FOLDER)
        files = [{
            'name': file,
            'size': os.path.getsize(os.path.join(UPLOAD_FOLDER, file)),
            'modified': os.path.getmtime(os.path.join(UPLOAD_FOLDER, file))
        } for file in files]
        # Sort files by modified time in descending order (newest first)
        files.sort(key=lambda x: x['modified'], reverse=True)
        return jsonify(files)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/files/<filename>', methods=['DELETE'])
def delete_file(filename):
    try:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        if os.path.exists(file_path):
            os.remove(file_path)
            return jsonify({'message': f'File {filename} deleted successfully'}), 200
        else:
            return jsonify({'error': 'File not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def notify_file_upload(filename):
    file_path = os.path.join(UPLOAD_FOLDER, filename)
    file_data = {
        'name': filename,
        'size': os.path.getsize(file_path),
        'modified': os.path.getmtime(file_path)
    }
    socketio.emit('file_uploaded', file_data)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
