import os
import requests
import pytz
from datetime import datetime
from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from apscheduler.schedulers.background import BackgroundScheduler

# -------------------- Timezone --------------------
LOCAL_TZ = pytz.timezone("Africa/Maseru")  # Lesotho timezone

# -------------------- Flask Setup --------------------
app = Flask(__name__)
app.config['SECRET_KEY'] = 'supersecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['UPLOAD_FOLDER'] = 'uploads'

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

# -------------------- Webhook URLs --------------------
WEBHOOK_SEND_FILE = "https://hook.eu2.make.com/utfnnaocu8e6du73i7c2es7qfsxjz2du"
WEBHOOK_POST = "https://hook.eu2.make.com/ohxlktclpc5btf9vtpssxtuubzl3ca8u"

# -------------------- Models --------------------
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(200), nullable=False)
    category = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class Content(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default="pending")  # pending, approved, rejected, posted
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    approved_at = db.Column(db.DateTime, nullable=True)
    scheduled_time = db.Column(db.DateTime, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# -------------------- Scheduler --------------------
scheduler = BackgroundScheduler()

def post_scheduled_content():
    with app.app_context():
        now = datetime.now(LOCAL_TZ)
        scheduled_contents = Content.query.filter(
            Content.status == "approved",
            Content.scheduled_time != None,
            Content.scheduled_time <= now
        ).all()

        if scheduled_contents:
            print(f"[Scheduler] Found {len(scheduled_contents)} scheduled posts")
        else:
            print(f"[Scheduler] Found 0 scheduled posts at {now}")

        for content in scheduled_contents:
            try:
                requests.post(WEBHOOK_POST, json={"content": content.text})
                content.status = "posted"
                db.session.commit()
                print(f"✅ Posted content ID {content.id}")
            except Exception as e:
                print("❌ Error sending content:", e)

scheduler.add_job(func=post_scheduled_content, trigger="interval", seconds=60)
scheduler.start()

# -------------------- Routes --------------------
@app.route('/')
def index():
    return render_template("index.html")

@app.route('/about')
def about():
    return render_template("about.html")

# -------------------- Auth --------------------
@app.route('/signup', methods=['GET','POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])
        if User.query.filter_by(username=username).first():
            flash("Username already exists!", "danger")
            return redirect(url_for('signup'))
        user = User(username=username, password=password)
        db.session.add(user)
        db.session.commit()
        flash("Account created successfully!", "success")
        return redirect(url_for('login'))
    return render_template("signup.html")

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash("Invalid credentials!", "danger")
    return render_template("login.html")

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# -------------------- Dashboard --------------------
@app.route('/dashboard')
@login_required
def dashboard():
    return render_template("dashboard_base.html")

# -------------------- File Upload --------------------
@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_file():
    if request.method == 'POST':
        file = request.files.get("file")
        description = request.form.get("description", "")

        if file:
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            file.save(filepath)

            # Send to Make.com
            with open(filepath, 'rb') as f:
                files = {'file': (filename, f, file.mimetype)}
                data = {'description': description, 'user': current_user.username}
                response = requests.post(WEBHOOK_SEND_FILE, files=files, data=data)

            if response.status_code == 200:
                flash("File uploaded successfully and sent to Make.com!", "success")
            else:
                flash(f"File uploaded locally, but Make.com returned {response.status_code}", "warning")

            return redirect(url_for('upload_file'))

    return render_template("upload_file.html")

# -------------------- Content Management --------------------
@app.route('/pending')
@login_required
def pending_content():
    pending = Content.query.filter_by(status="pending").all()
    return render_template("pending_content.html", contents=pending)

@app.route('/approved')
@login_required
def approved_content():
    approved = Content.query.filter_by(status="approved").all()
    return render_template("approved_content.html", contents=approved)

@app.route('/posted')
@login_required
def posted_content():
    posted = Content.query.filter_by(status="posted").all()
    return render_template("posted_content.html", contents=posted)

# -------------------- Approve / Reject --------------------
@app.route("/approve/<int:content_id>", methods=["POST"])
@login_required
def approve(content_id):
    content = Content.query.get_or_404(content_id)
    schedule_time = request.form.get("schedule_time")
    
    if schedule_time:
        try:
            # Convert HTML datetime-local string to timezone-aware datetime
            naive_dt = datetime.fromisoformat(schedule_time)
            aware_dt = LOCAL_TZ.localize(naive_dt)

            content.scheduled_time = aware_dt
            content.status = "approved"
            content.approved_at = datetime.now(LOCAL_TZ)
            flash(f"Content scheduled for {aware_dt.strftime('%Y-%m-%d %H:%M')}", "success")
        except Exception as e:
            print("Error parsing schedule time:", e)
            flash("Invalid schedule time format!", "danger")
    else:
        # Post immediately
        try:
            requests.post(WEBHOOK_POST, json={"content": content.text})
            content.status = "posted"
            content.approved_at = datetime.now(LOCAL_TZ)
            flash("Content approved and posted immediately!", "success")
        except Exception as e:
            print("Error posting content immediately:", e)
            content.status = "error"
            flash("Failed to post content immediately!", "danger")

    db.session.commit()
    return redirect(url_for("pending_content"))

@app.route("/reject/<int:content_id>", methods=["POST"])
@login_required
def reject(content_id):
    content = Content.query.get_or_404(content_id)
    content.status = "rejected"
    db.session.commit()
    flash("Content rejected!", "danger")
    return redirect(url_for('pending_content'))

# -------------------- Facebook OAuth Callback --------------------
@app.route("/fb_callback")
def fb_callback():
    code = request.args.get("code")
    error = request.args.get("error")

    if code:
        return render_template("fb_callback.html", content="Authorization successful!")
    elif error:
        return render_template("fb_callback.html", content=f"Authorization failed: {error}")
    else:
        return render_template("fb_callback.html", content="No response received from Facebook.")

# -------------------- API Endpoint --------------------
@app.route("/receive_content", methods=["POST"])
def receive_content():
    data = request.json
    text = data.get("content")
    if text:
        new_content = Content(text=text, status="pending", user_id=None)
        db.session.add(new_content)
        db.session.commit()
        return {"message": "Content received"}, 200
    return {"message": "No content received"}, 400

# -------------------- Run App --------------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
