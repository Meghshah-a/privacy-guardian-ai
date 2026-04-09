# 🛡️ AI Privacy Guardian

An AI-powered system built to protect users from real-world scams by detecting and preventing sensitive data leakage such as OTPs, passwords, and personal information from images, text, and voice inputs.

---

## 🚀 Features

* 🔍 Detects OTP and sensitive data from screenshots using OCR
* 🧠 Identifies scam and phishing messages using NLP techniques
* 🎙️ Analyzes voice input via speech-to-text for scam detection
* ⚡ Real-time detection and instant feedback
* 🔴 Risk classification (Safe / Medium / High)
* ⚠️ Alerts users before sensitive data is shared

---

## 🧠 How It Works

1. **User Input** → Image / Text / Audio
2. **Data Extraction** → OCR / Speech-to-Text
3. **Processing** → Text cleaning and analysis
4. **Detection Engine** → Regex + keyword-based NLP
5. **Risk Scoring** → Classifies level of threat
6. **Output** → Alerts + highlighted sensitive data

---

## 🔄 System Flow

Input → Extraction → Processing → Detection → Risk Analysis → Output

---

## 📊 Tech Stack

* **Frontend:** HTML, CSS, JavaScript
* **Backend:** Python (Flask)
* **Real-Time Communication:** Socket.IO
* **AI Tools:** Tesseract OCR, NLP, Regex

---

## 📁 Project Structure

* `app.py` → Main backend server
* `text_detector.py` → Text-based scam detection
* `image_detector.py` → OCR-based image processing
* `voice_detector.py` → Audio analysis
* `frontend.zip` → User interface
* `dataset_AI-otp.zip` → Custom dataset (images, text, audio)

---

## 📊 Dataset

A custom dataset was created to simulate real-world scenarios, including:

* OTP-based messages and screenshots
* Scam and phishing text samples
* Normal conversations for comparison
* Synthetic audio generated using text-to-speech

---

## ▶️ How to Run

```bash
pip install -r requirements.txt
python app.py
```

---

## 🎯 Use Case

This system helps users avoid fraud by detecting sensitive information before it is shared, making it useful for preventing OTP scams, phishing attacks, and accidental data leaks.

---

## 👥 Team

**Malware Minds**

---

## 🏆 Hackathon Project

Built during a 36-hour hackathon to address real-world privacy and cybersecurity challenges.
