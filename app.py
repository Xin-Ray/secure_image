import os
from flask import Flask, render_template, request, redirect, url_for, jsonify, flash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from models import db, User, ImageAnalysis
from PIL import Image
from PIL.ExifTags import TAGS
from werkzeug.utils import secure_filename
import json
from PIL.TiffImagePlugin import IFDRational
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from cryptography.fernet import Fernet

load_dotenv()

env_fernet_key = os.getenv('FERNET_KEY')
if env_fernet_key is None:
    env_fernet_key = Fernet.generate_key()
cipher_suite = Fernet(env_fernet_key)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('login success！', 'success')
            return redirect(url_for('index'))
        else:
            flash('wrong account name or password', 'danger')
            return redirect(url_for('login'))
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/upload', methods=['POST'])
@login_required
def upload():
    if 'file' not in request.files:
        flash('No file part')
        return redirect(request.url)
    file = request.files['file']
    if file.filename == '':
        flash('No selected file')
        return redirect(request.url)

    if file:
        filename = secure_filename(file.filename)
        save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(save_path)

        metadata = extract_metadata(save_path)

        metadata_json = json.dumps(metadata, cls=CustomJSONEncoder)
        encrypted_metadata = cipher_suite.encrypt(metadata_json.encode())

        analysis = ImageAnalysis(
            user_id=current_user.id,
            filename=filename,
            metadata_json=encrypted_metadata.decode()
        )
        db.session.add(analysis)
        db.session.commit()

        return render_template('result.html', filename=filename, metadata=metadata)


class CustomJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, IFDRational):
            return float(obj)
        return super().default(obj)


def extract_metadata(filename):
    metadata = {}
    try:
        file_extension = filename.lower().split('.')[-1]

        if file_extension == 'png':
            image = Image.open(filename)
            metadata['file_name'] = filename
            metadata['file_type'] = 'PNG'
            metadata['file_type_extension'] = 'png'
            metadata['mime_type'] = 'image/png'
            metadata['image_width'] = image.width
            metadata['image_height'] = image.height
            metadata['image_size'] = f"{image.width}x{image.height}"
            metadata['megapixels'] = round((image.width * image.height) / 1e6, 3)
            metadata['bit_depth'] = image.bits
            metadata['color_type'] = image.mode

            with open(filename, 'rb') as f:
                f.seek(8)
                while True:
                    length_bytes = f.read(4)
                    if not length_bytes:
                        break
                    length = struct.unpack('>I', length_bytes)[0]
                    chunk_type = f.read(4).decode('ascii')

                    if chunk_type == 'pHYs':
                        data = f.read(length)
                        pixels_per_unit_x, pixels_per_unit_y, unit = struct.unpack('>IIB', data)
                        unit_str = 'meters' if unit == 1 else 'unknown'
                        metadata['pixels_per_unit_x'] = pixels_per_unit_x
                        metadata['pixels_per_unit_y'] = pixels_per_unit_y
                        metadata['pixel_units'] = unit_str

                    elif chunk_type == 'gAMA':
                        data = f.read(length)
                        gamma = struct.unpack('>I', data)[0] / 100000
                        metadata['gamma'] = gamma

                    elif chunk_type == 'sRGB':
                        data = f.read(length)
                        rendering_intent = data[0]
                        rendering_intent_str = {
                            0: 'Perceptual',
                            1: 'Relative colorimetric',
                            2: 'Saturation',
                            3: 'Absolute colorimetric'
                        }.get(rendering_intent, 'unknown')
                        metadata['srgb_rendering'] = rendering_intent_str

                    else:
                        f.seek(length + 4, 1)

        elif file_extension in ['jpg', 'jpeg']:
            image = Image.open(filename)
            metadata['file_name'] = filename
            metadata['file_type'] = 'JPEG'
            metadata['file_type_extension'] = file_extension
            metadata['mime_type'] = 'image/jpeg'
            metadata['image_width'] = image.width
            metadata['image_height'] = image.height
            metadata['image_size'] = f"{image.width}x{image.height}"
            metadata['megapixels'] = round((image.width * image.height) / 1e6, 3)

            if hasattr(image, '_getexif'):
                exifdata = image._getexif()
                if exifdata:
                    metadata['has_camera_metadata'] = 'Camera-related EXIF metadata found'
                    for tag, value in exifdata.items():
                        tagname = TAGS.get(tag, tag)
                        metadata[tagname] = value
                else:
                    metadata['has_camera_metadata'] = 'No camera-related EXIF metadata found'
            else:
                metadata['has_camera_metadata'] = 'No camera-related EXIF metadata found'

    except Exception as e:
        print(f"Error extracting metadata: {e}")

    return metadata


@app.route('/history')
@login_required
def history():
    analyses = ImageAnalysis.query.filter_by(user_id=current_user.id).all()
    history_data = []
    for analysis in analyses:
        encrypted_metadata = analysis.metadata_json.encode()
        decrypted_metadata = cipher_suite.decrypt(encrypted_metadata).decode()
        metadata = json.loads(decrypted_metadata)
        history_data.append({
            'filename': analysis.filename,
            'metadata': metadata
        })
    return render_template('history.html', history=history_data)


# API 端点部分

# 用户注册 API
@app.route('/api/register', methods=['POST'])
def api_register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"message": "Username and password are required"}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({"message": "Username already exists"}), 400

    hashed_password = generate_password_hash(password)
    new_user = User(username=username, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "User registered successfully"}), 201


# 用户登录 API
@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=username).first()
    if user and check_password_hash(user.password, password):
        login_user(user)
        return jsonify({"message": "User logged in successfully"}), 200
    return jsonify({"message": "Invalid username or password"}), 401


# 用户注销 API
@app.route('/api/logout', methods=['POST'])
@login_required
def api_logout():
    logout_user()
    return jsonify({"message": "User logged out successfully"}), 200


# 图像上传和元数据提取 API
@app.route('/api/upload', methods=['POST'])
@login_required
def api_upload():
    if 'file' not in request.files:
        return jsonify({"message": "No file part"}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({"message": "No selected file"}), 400

    if file:
        filename = secure_filename(file.filename)
        save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(save_path)

        metadata = extract_metadata(save_path)

        metadata_json = json.dumps(metadata, cls=CustomJSONEncoder)
        encrypted_metadata = cipher_suite.encrypt(metadata_json.encode())

        analysis = ImageAnalysis(
            user_id=current_user.id,
            filename=filename,
            metadata_json=encrypted_metadata.decode()
        )
        db.session.add(analysis)
        db.session.commit()

        return jsonify({"message": "Image uploaded and metadata extracted successfully", "metadata": metadata}), 201


# 获取用户特定历史记录 API
@app.route('/api/history', methods=['GET'])
@login_required
def api_history():
    analyses = ImageAnalysis.query.filter_by(user_id=current_user.id).all()
    history_data = []
    for analysis in analyses:
        encrypted_metadata = analysis.metadata_json.encode()
        decrypted_metadata = cipher_suite.decrypt(encrypted_metadata).decode()
        metadata = json.loads(decrypted_metadata)
        history_data.append({
            'filename': analysis.filename,
            'metadata': metadata
        })
    return jsonify({"history": history_data}), 200


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)