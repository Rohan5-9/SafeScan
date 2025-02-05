import os
import hashlib
from flask import Flask, request, jsonify
from werkzeug.utils import secure_filename
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # Allow frontend to communicate with backend

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Example malicious hash database
malicious_hashes = {
    "e99a18c428cb38d5f260853678922e03",  # Example MD5 hash
    "d4735e3a265e16eee03f59718b9b5d03",  # Example SHA256 hash
}

def calculate_file_hash(file_path, hash_algorithm="md5"):
    """Calculate the hash of a file."""
    hash_func = hashlib.new(hash_algorithm)
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_func.update(chunk)
        return hash_func.hexdigest()
    except Exception as e:
        return str(e)

@app.route("/scan", methods=["POST"])
def scan_file():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No file selected"}), 400

    filename = secure_filename(file.filename)
    file_path = os.path.join(UPLOAD_FOLDER, filename)
    file.save(file_path)

    file_hash = calculate_file_hash(file_path)
    
    # Check if file hash matches known malware
    is_malicious = file_hash in malicious_hashes

    # Delete file after scanning (optional)
    os.remove(file_path)

    return jsonify({"filename": filename, "malicious": is_malicious})

if __name__ == "__main__":
    app.run(debug=True)
