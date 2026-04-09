from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import json
from datetime import datetime

# ── Import detectors ──────────────────────────────────────────────────
from text_detector  import detect_text_threat
from image_detector import detect_image_threat
from voice_detector import detect_voice_threat

# ── Import protection ─────────────────────────────────────────────────
from protection.masker  import mask_result
from protection.blocker import block_if_high_risk

# ── Import alerts ─────────────────────────────────────────────────────
from alerts.alert_engine import trigger_alert

# ── Import database ───────────────────────────────────────────────────
from database.db import save_scan

app = Flask(__name__)
CORS(app)

# ── Ensure folders exist ──────────────────────────────────────────────
os.makedirs("logs", exist_ok=True)
os.makedirs("database", exist_ok=True)

# ── Logger ────────────────────────────────────────────────────────────
def log_result(scan_type, result):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    is_threat = result.get("is_threat", False)

    log_file = "logs/threat_log.txt" if is_threat else "logs/safe_log.txt"

    with open(log_file, "a") as f:
        f.write(f"[{timestamp}] [{scan_type.upper()}] {json.dumps(result)}\n")

# ── Health check ──────────────────────────────────────────────────────
@app.route('/')
def home():
    return jsonify({"status": "DeepFence Backend Running 🚀"})

# ── TEXT SCAN ─────────────────────────────────────────────────────────
@app.route('/scan_text', methods=['POST'])   # ✅ FIXED ROUTE
def scan_text():
    try:
        data = request.get_json()
        text = data.get("text", "").strip()

        if not text:
            return jsonify({"error": "No text provided"}), 400

        result = detect_text_threat(text)

        result, _ = mask_result(result)
        block = block_if_high_risk(result)

        result["block"] = block

        trigger_alert(result)
        log_result("text", result)
        save_scan("text", result)

        status_code = 403 if block.get("blocked") else 200
        return jsonify(result), status_code

    except Exception as e:
        with open("logs/error_log.txt", "a") as f:
            f.write(f"[{datetime.now()}] TEXT ERROR: {str(e)}\n")
        return jsonify({"error": str(e)}), 500

# ── IMAGE SCAN ────────────────────────────────────────────────────────
@app.route('/scan_image', methods=['POST'])   # ✅ FIXED ROUTE
def scan_image():
    try:
        if 'file' not in request.files:
            return jsonify({"error": "No image uploaded"}), 400

        file = request.files['file']
        image_bytes = file.read()

        if not image_bytes:
            return jsonify({"error": "Empty file"}), 400

        result = detect_image_threat(image_bytes)

        result, _ = mask_result(result)
        block = block_if_high_risk(result)

        result["block"] = block

        trigger_alert(result)
        log_result("image", result)
        save_scan("image", result)

        status_code = 403 if block.get("blocked") else 200
        return jsonify(result), status_code

    except Exception as e:
        with open("logs/error_log.txt", "a") as f:
            f.write(f"[{datetime.now()}] IMAGE ERROR: {str(e)}\n")
        return jsonify({"error": str(e)}), 500

# ── VOICE SCAN ────────────────────────────────────────────────────────
@app.route('/scan_audio', methods=['POST'])   # ✅ FIXED ROUTE
def scan_voice():
    try:
        if 'file' not in request.files:
            return jsonify({"error": "No audio uploaded"}), 400

        file = request.files['file']
        audio_bytes = file.read()

        if not audio_bytes:
            return jsonify({"error": "Empty audio file"}), 400

        result = detect_voice_threat(audio_bytes)

        result, _ = mask_result(result)
        block = block_if_high_risk(result)

        result["block"] = block

        trigger_alert(result)
        log_result("voice", result)
        save_scan("voice", result)

        status_code = 403 if block.get("blocked") else 200
        return jsonify(result), status_code

    except Exception as e:
        with open("logs/error_log.txt", "a") as f:
            f.write(f"[{datetime.now()}] VOICE ERROR: {str(e)}\n")
        return jsonify({"error": str(e)}), 500

# ── RUN APP ───────────────────────────────────────────────────────────
if __name__ == '__main__':
    app.run(debug=True)