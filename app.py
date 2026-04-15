from flask import Flask, render_template, request, redirect, url_for, session
import os
import json
import random
import hashlib
from datetime import datetime
import boto3
from botocore.exceptions import BotoCoreError, ClientError

app = Flask(__name__)
app.secret_key = "pest_warning_secret_key"

AWS_REGION = os.getenv("AWS_REGION", "ap-south-1")
SNS_TOPIC_ARN = os.getenv(
    "SNS_TOPIC_ARN",
    "arn:aws:sns:ap-south-1:123456789012:pest-alert-topic"
)

USERS_FILE = "users.json"
HISTORY_FILE = "pest_history.json"

try:
    sns_client = boto3.client("sns", region_name=AWS_REGION)
except Exception:
    sns_client = None


def load_json_file(filename):
    if not os.path.exists(filename):
        return []
    try:
        with open(filename, "r", encoding="utf-8") as file:
            return json.load(file)
    except Exception:
        return []


def save_json_file(filename, data):
    with open(filename, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=4)


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


def generate_otp():
    return str(random.randint(100000, 999999))


def find_user_by_email(email):
    users = load_json_file(USERS_FILE)
    for user in users:
        if user["email"].lower() == email.lower():
            return user
    return None


def register_user(name, address, phone, email, password):
    users = load_json_file(USERS_FILE)

    for user in users:
        if user["email"].lower() == email.lower():
            return False, "Email already registered."

    new_user = {
        "id": len(users) + 1,
        "name": name,
        "address": address,
        "phone": phone,
        "email": email,
        "password": hash_password(password),
        "created_at": datetime.now().strftime("%d-%m-%Y %H:%M")
    }

    users.append(new_user)
    save_json_file(USERS_FILE, users)
    return True, "Registration successful. Please login."


def validate_login(email, password):
    user = find_user_by_email(email)
    if not user:
        return False, None

    if user["password"] == hash_password(password):
        return True, user

    return False, None


def send_verification_code(phone, email, otp_code):
    """
    Demo OTP sender.
    Later you can replace this with AWS SNS or SES.
    """
    print(f"OTP for {email} / {phone}: {otp_code}")
    return True, f"Verification code sent. Demo OTP: {otp_code}"


def send_sns_alert(message, subject="Pest Outbreak Early Warning Alert"):
    if not sns_client:
        return False, "SNS client not configured."

    try:
        response = sns_client.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=subject,
            Message=message
        )
        return True, response.get("MessageId", "No MessageId")
    except (BotoCoreError, ClientError) as e:
        return False, str(e)
    except Exception as e:
        return False, str(e)


def calculate_pest_risk(temperature, humidity, rainfall, pest_sightings, leaf_damage):
    score = 0

    if 20 <= temperature <= 35:
        score += 20

    if humidity >= 70:
        score += 20

    if rainfall >= 40:
        score += 15

    if pest_sightings >= 5:
        score += 25
    elif pest_sightings >= 2:
        score += 15

    if leaf_damage >= 50:
        score += 20
    elif leaf_damage >= 20:
        score += 10

    if score >= 70:
        return "High", score
    elif score >= 40:
        return "Medium", score
    return "Low", score


def get_recommendations(risk_level):
    if risk_level == "High":
        return {
            "methods": [
                "Inspect the crop field immediately and isolate affected areas.",
                "Use expert-recommended pesticide or organic pest control.",
                "Remove infected leaves and plant parts.",
                "Place pest traps in multiple sections of the field.",
                "Inform nearby farmers and monitor spread."
            ],
            "instructions": [
                "Check the field every morning and evening.",
                "Do not overwater the crop.",
                "Wear gloves and mask during treatment.",
                "Keep children and animals away from treated zones.",
                "Maintain a daily pest observation record."
            ]
        }

    if risk_level == "Medium":
        return {
            "methods": [
                "Monitor the crop closely for the next few days.",
                "Use sticky traps or light traps.",
                "Improve field cleanliness and remove weeds.",
                "Use preventive bio-pesticides if available.",
                "Maintain plant spacing for better airflow."
            ],
            "instructions": [
                "Inspect the underside of leaves daily.",
                "Avoid excess fertilizer use.",
                "Balance irrigation and avoid standing water.",
                "Watch for increase in insect count.",
                "Take photos of affected plants for comparison."
            ]
        }

    return {
        "methods": [
            "Continue normal crop care and preventive monitoring.",
            "Keep field surroundings clean.",
            "Use healthy seeds and resistant varieties if available.",
            "Encourage beneficial insects.",
            "Track weather conditions regularly."
        ],
        "instructions": [
            "Inspect the field every 2 to 3 days.",
            "Remove dry leaves and crop waste.",
            "Maintain proper irrigation practices.",
            "Keep a simple crop health notebook.",
            "Be extra alert during rainy and humid days."
        ]
    }


def add_history_record(record):
    history = load_json_file(HISTORY_FILE)
    history.insert(0, record)
    save_json_file(HISTORY_FILE, history)


@app.route("/")
def root():
    return redirect(url_for("home"))


@app.route("/home")
def home():
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if "user_email" in session:
        return redirect(url_for("dashboard"))

    message = None
    error = None

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        address = request.form.get("address", "").strip()
        phone = request.form.get("phone", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "").strip()
        confirm_password = request.form.get("confirm_password", "").strip()

        if not all([name, address, phone, email, password, confirm_password]):
            error = "Please fill in all registration fields."
        elif password != confirm_password:
            error = "Passwords do not match."
        elif len(password) < 6:
            error = "Password must be at least 6 characters."
        else:
            success, msg = register_user(name, address, phone, email, password)
            if success:
                message = msg
            else:
                error = msg

    return render_template("register.html", message=message, error=error)


@app.route("/login", methods=["GET", "POST"])
def login():
    if "user_email" in session:
        return redirect(url_for("dashboard"))

    error = None

    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "").strip()

        valid, user = validate_login(email, password)

        if valid:
            otp_code = generate_otp()
            session["pending_user_email"] = user["email"]
            session["pending_user_name"] = user["name"]
            session["pending_user_phone"] = user["phone"]
            session["pending_otp"] = otp_code

            success, _ = send_verification_code(user["phone"], user["email"], otp_code)

            if success:
                return redirect(url_for("verify_login"))
            else:
                error = "Could not send verification code."
        else:
            error = "Invalid email or password."

    return render_template("login.html", error=error)


@app.route("/verify", methods=["GET", "POST"])
def verify_login():
    if "pending_user_email" not in session:
        return redirect(url_for("login"))

    error = None
    demo_otp = session.get("pending_otp")

    if request.method == "POST":
        entered_otp = request.form.get("otp", "").strip()
        saved_otp = session.get("pending_otp")

        if entered_otp == saved_otp:
            session["user_email"] = session.get("pending_user_email")
            session["user_name"] = session.get("pending_user_name")
            session["user_phone"] = session.get("pending_user_phone")

            session.pop("pending_user_email", None)
            session.pop("pending_user_name", None)
            session.pop("pending_user_phone", None)
            session.pop("pending_otp", None)

            return redirect(url_for("dashboard"))
        else:
            error = "Invalid verification code."

    return render_template("verify.html", error=error, demo_otp=demo_otp)


@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    if "user_email" not in session:
        return redirect(url_for("login"))

    result = None
    alert_status = None
    methods = []
    instructions = []

    if request.method == "POST":
        farmer_name = request.form.get("farmer_name", "").strip()
        location = request.form.get("location", "").strip()
        crop = request.form.get("crop", "").strip()

        if not farmer_name or not location or not crop:
            alert_status = "Please fill all text fields."
            return render_template(
                "dashboard.html",
                result=None,
                alert_status=alert_status,
                methods=[],
                instructions=[],
                user_name=session.get("user_name")
            )

        try:
            temperature = float(request.form.get("temperature", 0))
            humidity = float(request.form.get("humidity", 0))
            rainfall = float(request.form.get("rainfall", 0))
            pest_sightings = int(request.form.get("pest_sightings", 0))
            leaf_damage = float(request.form.get("leaf_damage", 0))
        except ValueError:
            alert_status = "Please enter valid numeric values."
            return render_template(
                "dashboard.html",
                result=None,
                alert_status=alert_status,
                methods=[],
                instructions=[],
                user_name=session.get("user_name")
            )

        risk_level, score = calculate_pest_risk(
            temperature, humidity, rainfall, pest_sightings, leaf_damage
        )

        if risk_level == "High":
            recommendation = "Immediate action needed. High chance of pest outbreak."
        elif risk_level == "Medium":
            recommendation = "Moderate risk. Monitor the crop and take preventive action."
        else:
            recommendation = "Low risk. Continue regular crop care and observation."

        result = {
            "farmer_name": farmer_name,
            "location": location,
            "crop": crop,
            "temperature": temperature,
            "humidity": humidity,
            "rainfall": rainfall,
            "pest_sightings": pest_sightings,
            "leaf_damage": leaf_damage,
            "risk_level": risk_level,
            "score": score,
            "recommendation": recommendation
        }

        guidance = get_recommendations(risk_level)
        methods = guidance["methods"]
        instructions = guidance["instructions"]

        record = {
            "user_email": session.get("user_email"),
            "user_name": session.get("user_name"),
            "date": datetime.now().strftime("%d-%m-%Y %H:%M"),
            "farmer_name": farmer_name,
            "location": location,
            "crop": crop,
            "temperature": temperature,
            "humidity": humidity,
            "rainfall": rainfall,
            "pest_sightings": pest_sightings,
            "leaf_damage": leaf_damage,
            "risk_level": risk_level,
            "score": score,
            "recommendation": recommendation
        }
        add_history_record(record)

        if risk_level == "High":
            message = f"""
Pest Outbreak Early Warning Alert

User: {session.get('user_name')}
Farmer Name: {farmer_name}
Location: {location}
Crop: {crop}
Temperature: {temperature} °C
Humidity: {humidity} %
Rainfall: {rainfall} mm
Pest Sightings: {pest_sightings}
Leaf Damage: {leaf_damage} %

Predicted Risk Level: {risk_level}
Risk Score: {score}

Recommendation:
{recommendation}
"""
            success, response_msg = send_sns_alert(message)
            if success:
                alert_status = f"SNS alert sent successfully. Message ID: {response_msg}"
            else:
                alert_status = f"SNS alert not sent: {response_msg}"

    return render_template(
        "dashboard.html",
        result=result,
        alert_status=alert_status,
        methods=methods,
        instructions=instructions,
        user_name=session.get("user_name")
    )


@app.route("/history")
def history():
    if "user_email" not in session:
        return redirect(url_for("login"))

    all_records = load_json_file(HISTORY_FILE)
    user_records = [
        record for record in all_records
        if record.get("user_email") == session.get("user_email")
    ]

    return render_template(
        "history.html",
        records=user_records,
        user_name=session.get("user_name")
    )


@app.route("/guidance")
def guidance():
    if "user_email" not in session:
        return redirect(url_for("login"))

    return render_template("guidance.html", user_name=session.get("user_name"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    if not os.path.exists(USERS_FILE):
        save_json_file(USERS_FILE, [])
    if not os.path.exists(HISTORY_FILE):
        save_json_file(HISTORY_FILE, [])

    app.run(debug=True, host="0.0.0.0", port=5000)