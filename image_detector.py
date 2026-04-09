import re
import io
import os
import numpy as np
from PIL import Image

# Tesseract setup
TESSERACT_AVAILABLE = False
try:
    import pytesseract
    for path in [
        r'C:\Program Files\Tesseract-OCR\tesseract.exe',
        '/usr/bin/tesseract', '/usr/local/bin/tesseract'
    ]:
        if os.path.exists(path):
            pytesseract.pytesseract.tesseract_cmd = path
            break
    TESSERACT_AVAILABLE = True
    print("✅ Tesseract loaded")
except ImportError:
    print("⚠️  Tesseract not available")

# EasyOCR setup
OCR_READER = None
try:
    import easyocr
    OCR_READER = easyocr.Reader(['en'], gpu=False)
    print("✅ EasyOCR loaded")
except ImportError:
    print("⚠️  EasyOCR not available")

SENSITIVE_PATTERNS = {
    "OTP":     r'\b\d{4,8}\b',
    "Aadhaar": r'\b\d{4}\s?\d{4}\s?\d{4}\b',
    "PAN":     r'\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b',
    "CVV":     r'\b\d{3}\b',
    "Card No": r'\b(?:\d{4}[-\s]?){4}\b',
    "Phone":   r'\b[6-9]\d{9}\b',
    "UPI":     r'\b[a-zA-Z0-9._%+-]+@[a-z]{3,}\b',
}

FORGERY_KEYWORDS = [
    "government of india", "aadhaar", "uid", "pan card",
    "verified", "certified", "official", "bank of", "state bank",
    "hdfc", "icici", "axis bank", "approved", "authorized",
    "payment successful", "transaction complete",
    "google pay", "phonepe", "paytm"
]

def detect_image_threat(image_bytes):
    if not image_bytes:
        return {"type": "image", "is_threat": False,
                "verdict": "❌ No image data", "risk_score": 0}
    try:
        image = Image.open(io.BytesIO(image_bytes)).convert("RGB")
    except Exception as e:
        return {"type": "image", "is_threat": False,
                "verdict": f"❌ Cannot open image: {e}", "risk_score": 0}

    w, h = image.size
    if w < 10 or h < 10:
        return {"type": "image", "is_threat": False,
                "verdict": "❌ Image too small", "risk_score": 0}

    image_meta     = {"width": w, "height": h, "format": str(image.format)}
    extracted_text = ""
    ocr_method     = "none"

    if OCR_READER:
        try:
            results        = OCR_READER.readtext(np.array(image))
            extracted_text = " ".join([r[1] for r in results])
            ocr_method     = "easyocr"
        except Exception as e:
            print(f"⚠️  EasyOCR failed: {e}")

    if not extracted_text and TESSERACT_AVAILABLE:
        try:
            extracted_text = pytesseract.image_to_string(image)
            ocr_method     = "tesseract"
        except Exception as e:
            print(f"⚠️  Tesseract failed: {e}")

    extracted_text = extracted_text.strip()

    sensitive_found = {}
    for label, pattern in SENSITIVE_PATTERNS.items():
        matches = re.findall(pattern, extracted_text)
        if matches:
            sensitive_found[label] = matches

    text_lower    = extracted_text.lower()
    forgery_flags = [kw for kw in FORGERY_KEYWORDS if kw in text_lower]

    risk  = 0
    if "OTP"     in sensitive_found: risk += 40
    if "Aadhaar" in sensitive_found: risk += 45
    if "PAN"     in sensitive_found: risk += 35
    if "Card No" in sensitive_found: risk += 40
    if "CVV"     in sensitive_found: risk += 40
    if "Phone"   in sensitive_found: risk += 20
    if "UPI"     in sensitive_found: risk += 25
    risk += min(len(forgery_flags) * 10, 30)
    risk  = min(risk, 100)

    is_threat = bool(sensitive_found) or len(forgery_flags) >= 2 or risk >= 40

    if risk >= 70:             verdict = "🚨 HIGH THREAT — Sensitive Data in Image"
    elif risk >= 40:           verdict = "⚠️  SUSPICIOUS — Possible Forged Document"
    elif len(forgery_flags)>0: verdict = "⚠️  WARNING — Official Document Detected"
    else:                      verdict = "✅ SAFE"

    return {
        "type": "image", "is_threat": bool(is_threat),
        "verdict": verdict, "risk_score": risk,
        "extracted_text": extracted_text, "sensitive_data": sensitive_found,
        "forgery_flags": forgery_flags, "ocr_method": ocr_method,
        "image_meta": image_meta,
    }
