import os, re, tempfile, wave, contextlib

WHISPER_AVAILABLE = False
whisper_model     = None
try:
    import whisper
    whisper_model     = whisper.load_model("base")
    WHISPER_AVAILABLE = True
    print("✅ Whisper loaded")
except: print("⚠️  Whisper not available")

GOOGLE_STT_AVAILABLE = False
try:
    import speech_recognition as sr
    RECOGNIZER           = sr.Recognizer()
    GOOGLE_STT_AVAILABLE = True
    print("✅ Google STT loaded as fallback")
except: print("⚠️  SpeechRecognition not installed")

ALLOWED_FORMATS = {'.wav','.mp3','.ogg','.flac','.m4a','.mp4'}

VOICE_KEYWORDS = [
    "otp","one time password","verification code","tell me the otp",
    "share your otp","bank account","account blocked","i am calling from",
    "calling from bank","reserve bank","rbi","urgent","immediately",
    "card number","credit card","debit card","cvv","pin number",
    "password","aadhaar","pan card","transfer money","send money",
    "upi","paytm","google pay","you have won","congratulations",
    "arrest","police","court","cyber crime","legal notice"
]

SENSITIVE_PATTERNS = {
    "OTP":     r'\b\d{4,8}\b',
    "Phone":   r'\b[6-9]\d{9}\b',
    "Aadhaar": r'\b\d{4}\s?\d{4}\s?\d{4}\b',
    "Card No": r'\b(?:\d{4}[-\s]?){4}\b',
}

DEEPFAKE_SIGNALS = [
    "this call is being recorded","automated message",
    "this is an automated","press 1 to","press 2 to","dial 1 for"
]

def get_wav_duration(path):
    try:
        with contextlib.closing(wave.open(path,'r')) as f:
            return round(f.getnframes() / float(f.getframerate()), 2)
    except: return 0.0

def detect_voice_threat(audio_bytes, extension=".wav"):
    if not audio_bytes:
        return {"type":"voice","is_threat":False,
                "verdict":"❌ No audio data","risk_score":0,"transcription":""}

    ext = extension.lower()
    if ext not in ALLOWED_FORMATS:
        return {"type":"voice","is_threat":False,
                "verdict":f"❌ Unsupported format: {ext}","risk_score":0,"transcription":""}

    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(suffix=ext, delete=False) as tmp:
            tmp.write(audio_bytes)
            tmp_path = tmp.name
    except Exception as e:
        return {"type":"voice","is_threat":False,
                "verdict":f"❌ Save error: {e}","risk_score":0,"transcription":""}

    audio_meta = {
        "format":       ext,
        "size_kb":      round(len(audio_bytes)/1024, 2),
        "duration_sec": get_wav_duration(tmp_path) if ext==".wav" else 0
    }

    transcription = ""
    stt_method    = "none"
    stt_confidence = 0.0

    if WHISPER_AVAILABLE and whisper_model:
        try:
            res            = whisper_model.transcribe(tmp_path)
            transcription  = res.get("text","").strip()
            stt_method     = "whisper"
            segs           = res.get("segments",[])
            if segs:
                avg = sum(s.get("avg_logprob",-1) for s in segs)/len(segs)
                stt_confidence = round(max(0, min(100,(avg+1)*100)),2)
        except Exception as e:
            print(f"⚠️  Whisper failed: {e}")

    if not transcription and GOOGLE_STT_AVAILABLE:
        try:
            with sr.AudioFile(tmp_path) as source:
                audio_data    = RECOGNIZER.record(source)
            transcription  = RECOGNIZER.recognize_google(audio_data)
            stt_method     = "google"
            stt_confidence = 75.0
        except Exception as e:
            print(f"⚠️  Google STT failed: {e}")

    try:
        if tmp_path and os.path.exists(tmp_path): os.unlink(tmp_path)
    except: pass

    if not transcription.strip():
        return {"type":"voice","is_threat":False,
                "verdict":"⚠️  Could not transcribe audio",
                "risk_score":0,"transcription":"","stt_method":stt_method,
                "audio_meta":audio_meta}

    text_lower       = transcription.lower()
    matched_keywords = [kw for kw in VOICE_KEYWORDS if kw in text_lower]

    sensitive_found  = {}
    for label, pattern in SENSITIVE_PATTERNS.items():
        matches = re.findall(pattern, transcription)
        if matches: sensitive_found[label] = matches

    deepfake_flags      = [s for s in DEEPFAKE_SIGNALS if s in text_lower]
    is_likely_synthetic = len(deepfake_flags) > 0

    risk  = 0
    if "OTP"     in sensitive_found: risk += 50
    if "Aadhaar" in sensitive_found: risk += 45
    if "Card No" in sensitive_found: risk += 40
    if "Phone"   in sensitive_found: risk += 20
    risk += min(len(matched_keywords)*8, 40)
    if is_likely_synthetic: risk += 20
    risk  = min(risk, 100)

    is_threat = (risk>=40 or bool(sensitive_found) or
                 len(matched_keywords)>=2 or is_likely_synthetic)

    if risk >= 70:           verdict = "🚨 HIGH THREAT — Scam Voice Detected"
    elif risk >= 40:         verdict = "⚠️  SUSPICIOUS — Possible Voice Phishing"
    elif is_likely_synthetic:verdict = "⚠️  WARNING — Synthetic Voice Detected"
    else:                    verdict = "✅ SAFE"

    return {
        "type":"voice","is_threat":bool(is_threat),"verdict":verdict,
        "risk_score":risk,"transcription":transcription,
        "matched_keywords":matched_keywords,"sensitive_data":sensitive_found,
        "deepfake_flags":deepfake_flags,"is_likely_synthetic":is_likely_synthetic,
        "stt_method":stt_method,"stt_confidence":stt_confidence,
        "audio_meta":audio_meta,
    }
