# Image Metadata Analysis Application

## Introduction
The Image Metadata Analysis Application is a web - based tool that enables users to register, log in, upload images, extract metadata from those images, and view their upload history. Built on the Flask framework, it offers a user - friendly interface and robust functionality while ensuring data security through encryption and proper authentication mechanisms.

## Features

### User Authentication
- **Registration**: Users can create new accounts by providing a unique username and a password. The password is hashed before being stored in the database to protect user information.
- **Login**: Registered users can log in using their username and password. The system verifies the credentials against the hashed passwords stored in the database.
- **Logout**: Logged - in users can log out at any time, terminating their current session.

### Image Upload and Metadata Extraction
- **Upload**: Authenticated users can upload image files (both JPEG and PNG formats are supported). The uploaded images are saved to a designated directory.
- **Metadata Extraction**: For JPEG images, the application extracts EXIF metadata if available. For PNG images, it parses specific chunks to retrieve relevant metadata such as image dimensions, color type, etc.

### History Viewing
- Users can view their past uploads, including the filenames and corresponding metadata of the images. The metadata is encrypted when stored in the database and decrypted when retrieved for viewing.

## Technical Details

### Back - end
- **Flask Framework**: Provides the foundation for the web application, handling routing, requests, and responses.
- **SQLite Database**: Stores user information and image analysis records. The database schema consists of two main tables: `User` and `ImageAnalysis`.
- **Encryption**: Uses the `cryptography` library's `Fernet` algorithm to encrypt and decrypt image metadata, ensuring data confidentiality.
- **Password Hashing**: Implements password hashing using `werkzeug.security` to protect user passwords.

### Front - end
- **HTML and Bootstrap**: Creates an intuitive and responsive user interface. The pages are designed to be easy to navigate and visually appealing.

## API Endpoints
- **User Authentication**:
  - `/api/register`: Allows new users to register.
  - `/api/login`: Enables registered users to log in.
  - `/api/logout`: Logs out the currently logged - in user.
- **Image Upload and Metadata Extraction**:
  - `/api/upload`: Handles image uploads and metadata extraction.
- **History Retrieval**:
  - `/api/history`: Returns the user's upload history.

## Installation and Setup
1. **Create a Virtual Environment**:
   ```bash
   python -m venv myenv
   source myenv/bin/activate  # For Linux/macOS
   myenv\Scripts\activate  # For Windows
   ```
2. **Install Dependencies**:
   ```bash
   pip install flask flask - sqlalchemy flask - login werkzeug.security pillow cryptography
   ```
3. **Configure the Application**:
   Set the necessary environment variables and database URI in the `app.py` file.
4. **Create the Database**:
   ```python
   from app import app, db
   with app.app_context():
       db.create_all()
   ```
5. **Run the Application**:
   ```bash
   python app.py
   ```

## Future Improvements
- Add more advanced image processing features, such as image resizing or watermarking.
- Implement a search function for the history page to allow users to quickly find specific images.
- Enhance the API to support more complex queries and operations. 
