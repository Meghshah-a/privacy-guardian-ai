import re
import joblib
import os

PHISHING_KEYWORDS = [
    "otp", "one time password", "password", "bank", "verify", "urgent",
    "suspended", "blocked", "click here", "limited time", "congratulations",
    "winner", "kyc", "expire", "immediately", "confirm your", "bank account",
    "free gift", "claim now", "act now", "your account", "login here",
    "reset password", "dear customer", "account will be", "last chance",
    "you have won", "selected", "transfer", "send money", "pin number",
    "credit card", "debit card", "unauthorized", "suspicious activity"
]

SENSITIVE_PATTERNS = {
    "OTP":     r'(?:otp|one.time.password|code|pin)[\s:is]*\b(\d{4,8})\b',
    "Aadhaar": r'\b\d{4}\s\d{4}\s\d{4}\b',
    "PAN":     r'\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b',
    "CVV":     r'\bCVV[:\s]*\d{3}\b',
    "Card No": r'\b(?:\d{4}[-\s]?){4}\b',
    "Phone":   r'\b[6-9]\d{9}\b',
    "Email":   r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b',
    "UPI":     r'\b[a-zA-Z0-9._%+-]+@[a-z]{3,}\b',
}

model = None
try:
    model_path = os.path.join(os.path.dirname(__file__), "models", "text_model.pkl")
    model      = joblib.load(model_path)
    print("✅ Text model loaded")
except FileNotFoundError:
    print("⚠️  text_model.pkl not found — rule-based only")
except Exception as e:
    print(f"⚠️  Model load failed: {e}")

def detect_text_threat(text):
    if not text or not text.strip():
        return {
            "type": "text", "is_threat": False,
            "verdict": "✅ SAFE", "risk_score": 0
        }

    text_lower = text.lower()

    matched_keywords = [kw for kw in PHISHING_KEYWORDS if kw in text_lower]

    sensitive_found = {}
    for label, pattern in SENSITIVE_PATTERNS.items():
        matches = re.findall(pattern, text, re.IGNORECASE)
        if matches:
            sensitive_found[label] = matches

    ml_label      = "unknown"
    ml_confidence = 0.0
    if model:
        try:
            prediction    = model.predict([text])[0]
            probabilities = model.predict_proba([text])[0]
            ml_confidence = round(probabilities[1] * 100, 2)
            ml_label      = "threat" if prediction == 1 else "safe"
        except Exception as e:
            ml_label = f"error: {e}"

    risk = 0
    if "OTP"     in sensitive_found: risk += 40
    if "Aadhaar" in sensitive_found: risk += 40
    if "PAN"     in sensitive_found: risk += 30
    if "Card No" in sensitive_found: risk += 35
    if "CVV"     in sensitive_found: risk += 35
    if "Phone"   in sensitive_found: risk += 20
    if "Email"   in sensitive_found: risk += 15
    if "UPI"     in sensitive_found: risk += 25
    risk += min(len(matched_keywords) * 8, 40)
    if ml_label == "threat": risk += 20
    risk = min(risk, 100)

    is_threat = (
        risk >= 40 or ml_label == "threat" or
        len(matched_keywords) >= 2 or bool(sensitive_found)
    )

    if risk >= 70:   verdict = "🚨 HIGH THREAT DETECTED"
    elif risk >= 40: verdict = "⚠️  SUSPICIOUS"
    else:            verdict = "✅ SAFE"

    return {
        "type": "text", "is_threat": bool(is_threat),
        "verdict": verdict, "risk_score": risk,
        "ml_prediction": ml_label, "ml_confidence": ml_confidence,
        "matched_keywords": matched_keywords,
        "sensitive_data": sensitive_found,
    }
