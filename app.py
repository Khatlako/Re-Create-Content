
import os
import calendar
import uuid
from datetime import datetime, timedelta
import pytz
from functools import wraps
import requests
import secrets
from flask import Flask, render_template, redirect, url_for, request, flash, jsonify, session
from flask import Flask, render_template, redirect, url_for, request, flash, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_migrate import Migrate
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Mail, Message
from apscheduler.schedulers.background import BackgroundScheduler
from flask_sqlalchemy import SQLAlchemy

# -------------------- Config --------------------
LOCAL_TZ = pytz.timezone("Africa/Maseru")

FB_APP_ID = "1211588177399102"
FB_APP_SECRET = "154b3c51109bb4169890d544d141d8f0"
FB_REDIRECT_URI = "https://re-create-content.onrender.com/facebook/callback" 

WEBHOOK_SEND_FILE = "https://hook.eu2.make.com/utfnnaocu8e6du73i7c2es7qfsxjz2du"
WEBHOOK_POST = "https://hook.eu2.make.com/ohxlktclpc5btf9vtpssxtuubzl3ca8u"
WEBHOOK_SUBSCRIPTION = "https://hook.eu2.make.com/xcgt6zuc2lxcpqp3vlhwpuspqswm77rf"
MAKE_WEBHOOK_URL = "https://hook.eu2.make.com/j64u5rj9rtsuczkrllgydwvsyy8xay2h"

# Ecocash USSD-push endpoint (the one you provided)
ECOCASH_API_URL = "https://dt-externalproxy-1.etl.co.ls/etl/salesagentpay/paymerchant/"

# -------------------- Flask Setup --------------------
app = Flask(__name__)
app.config["SECRET_KEY"] = "supersecretkey"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///site.db"
app.config["UPLOAD_FOLDER"] = "uploads"

# Mail configuration (adjust to your SMTP in production)
app.config.update(
    MAIL_SERVER="localhost",
    MAIL_PORT=25,
    MAIL_USE_TLS=False,
    MAIL_USE_SSL=False,
)

# -------------------- Extensions --------------------
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = "login"
mail = Mail(app)
s = URLSafeTimedSerializer(app.config["SECRET_KEY"])

# -------------------- Models --------------------
class User(db.Model, UserMixin):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True)
    password = db.Column(db.String(200), nullable=False)
    ecocash_number = db.Column(db.String(20), nullable=True)
    used_trial = db.Column(db.Boolean, default=False)

     # --- Facebook tokens ---
    facebook_page_id = db.Column(db.String(50), nullable=True)
    facebook_page_token = db.Column(db.Text, nullable=True)
    facebook_long_lived_token = db.Column(db.Text, nullable=True)
    facebook_business_id = db.Column(db.String(50), nullable=True)
    facebook_system_user_id = db.Column(db.String(50), nullable=True)
    facebook_system_user_token = db.Column(db.Text, nullable=True)
    facebook_permissions_granted = db.Column(db.Text, nullable=True)  # JSON list
    
    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

    @property
    def has_active_subscription(self):
        now = datetime.now(LOCAL_TZ)
        sub = Subscription.query.filter_by(user_id=self.id, status="active").first()
        if sub and sub.end_date:
            sub_end = sub.end_date
            if sub_end.tzinfo is None:
                sub_end = LOCAL_TZ.localize(sub_end)
            return sub_end >= now
        return False
    
    @property
    def subscription_type(self):
        sub = self.active_subscription
        if sub:
            return sub.type
        elif self.used_trial:
            return "Free Trial"
        return "None"
        
    @property
    def days_left(self):
        """Return remaining days for active subscription or trial"""
        now = datetime.now(LOCAL_TZ)
        sub = self.active_subscription
        if sub:
            delta = sub.end_date - now
            return max(delta.days, 0)
        elif self.used_trial:
            # Assuming you store trial start/end somewhere
            trial = Trial.query.filter_by(user_id=self.id).first()  # or your trial logic
            if trial:
                delta = trial.end_date - now
                return max(delta.days, 0)
        return 0

class Subscription(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(36), db.ForeignKey("user.id"), nullable=False)
    type = db.Column(db.String(50))
    start_date = db.Column(db.DateTime, nullable=False)
    end_date = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.String(20), default="active")
    amount_paid = db.Column(db.Float, default=0.0)
    payment_interval = db.Column(db.String(10), default="monthly")  # monthly or yearly

class Document(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    filename = db.Column(db.String(200), nullable=False)
    category = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.String(36), db.ForeignKey("user.id"), nullable=False)

class Content(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    text = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default="pending")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    approved_at = db.Column(db.DateTime, nullable=True)
    scheduled_time = db.Column(db.DateTime, nullable=True)
    user_id = db.Column(db.String(36), db.ForeignKey("user.id"), nullable=False)
    user = db.relationship("User", backref=db.backref("contents", lazy=True))

# -------------------- User Loader --------------------
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(str(user_id))

# -------------------- Decorators --------------------
def subscription_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.has_active_subscription:
            flash("Your subscription has expired. Please subscribe to access this feature.", "danger")
            return redirect(url_for("pricing"))  # <-- redirect to pricing instead of dashboard
        return f(*args, **kwargs)
    return decorated_function

# -------------------- Scheduler --------------------
scheduler = BackgroundScheduler()
def post_scheduled_content():
    with app.app_context():
        now = datetime.now(LOCAL_TZ)
        scheduled_contents = Content.query.filter(
            Content.status == "approved",
            Content.scheduled_time != None,
            Content.scheduled_time <= now,
        ).all()

        for content in scheduled_contents:
            try:
                response = requests.post(
                    WEBHOOK_POST,
                    json={
                        "content": content.text,
                        "username": content.user.username,
                        "user_id": content.user.id,
                    },
                    timeout=10
                )
                response.raise_for_status()  # Raises error if HTTP != 200
                content.status = "posted"
                db.session.commit()
                print(f"✅ Posted content {content.id}, response={response.status_code}")
            except Exception as e:
                import traceback
                print(f"❌ Failed to post content {content.id}: {e}")
                traceback.print_exc()
                
                
#--------------Token Refresh Automation---------------------
def refresh_system_user_tokens():
    with app.app_context():
        users = User.query.filter(User.facebook_system_user_token != None).all()
        for u in users:
            try:
                refresh_url = f"https://graph.facebook.com/v21.0/oauth/access_token"
                resp = requests.get(refresh_url, params={
                    "grant_type": "fb_exchange_token",
                    "client_id": FB_APP_ID,
                    "client_secret": FB_APP_SECRET,
                    "fb_exchange_token": u.facebook_system_user_token
                }, timeout=10).json()
                new_token = resp.get("access_token")
                if new_token:
                    u.facebook_system_user_token = new_token
                    db.session.commit()
            except Exception as e:
                print(f"❌ Failed refreshing FB token for user {u.id}: {e}")

scheduler.add_job(refresh_system_user_tokens, "interval", hours=12)


# -------------------- Routes --------------------

# -------------------- Home --------------------
@app.route("/")
def index():
    return render_template("index.html")

# -------------------- About --------------------
@app.route("/about")
def about():
    return render_template("about.html")
    
@app.route("/contact")
def contact():
    return render_template("contact.html")

@app.route("/help")
def help():
    return render_template("help_desk.html")


# -------------------- Facebook OAuth Initiation --------------------
@app.route("/connect-facebook")
def connect_facebook():
    scopes = [
        "public_profile",
        "email",
        "pages_show_list",
        "pages_read_engagement",
        "pages_manage_posts",
        "pages_manage_metadata",
        "pages_manage_engagement",
        "pages_read_user_content",
        "business_management"
    ]

    fb_auth_url = (
        "https://www.facebook.com/v21.0/dialog/oauth"
        "?client_id=" + FB_APP_ID +
        "&redirect_uri=" + FB_REDIRECT_URI +
        "&state=" + secrets.token_urlsafe(16) +
        "&auth_type=rerequest" +
        "&scope=" + ",".join(scopes)
    )

    return redirect(fb_auth_url)

@app.template_filter('strftime')
def _jinja2_filter_datetime(date, fmt='%Y-%m-%dT%H:%M'):
    if date is None:
        return ""
    return date.strftime(fmt)



# -------------------- Facebook OAuth Callback --------------------


@app.route("/facebook/callback")
@login_required
def facebook_callback():
    code = request.args.get("code")
    error = request.args.get("error")

    if error:
        flash(f"Facebook authorization failed: {error}", "danger")
        return redirect(url_for("dashboard"))

    if not code:
        flash("No authorization code received from Facebook.", "danger")
        return redirect(url_for("dashboard"))

    try:
        # -----------------------------
        # 1 Exchange code for short-lived user token
        # -----------------------------
        token_url = (
            f"https://graph.facebook.com/v21.0/oauth/access_token?"
            f"client_id={FB_APP_ID}&redirect_uri={FB_REDIRECT_URI}"
            f"&client_secret={FB_APP_SECRET}&code={code}"
        )
        resp = requests.get(token_url, timeout=10).json()
        short_lived_token = resp.get("access_token")
        if not short_lived_token:
            flash("Could not obtain short-lived user token.", "danger")
            return redirect(url_for("dashboard"))

        # -----------------------------
        # 2 Exchange for long-lived user token
        # -----------------------------
        long_token_url = (
            f"https://graph.facebook.com/v21.0/oauth/access_token?"
            f"grant_type=fb_exchange_token&client_id={FB_APP_ID}"
            f"&client_secret={FB_APP_SECRET}&fb_exchange_token={short_lived_token}"
        )
        long_resp = requests.get(long_token_url, timeout=10).json()
        long_lived_token = long_resp.get("access_token")
        if not long_lived_token:
            flash("Could not obtain long-lived user token.", "danger")
            return redirect(url_for("dashboard"))

        # -----------------------------
        # 3 Get user’s Facebook Pages
        # -----------------------------
        pages_url = f"https://graph.facebook.com/v21.0/me/accounts?access_token={long_lived_token}"
        pages_resp = requests.get(pages_url, timeout=10).json()
        pages = pages_resp.get("data", [])

        if not pages:
            flash("No Facebook Pages found for your account.", "danger")
            return redirect(url_for("dashboard"))

        # For simplicity, auto-select first page (or implement UI selection)
        page = pages[0]
        page_id = page["id"]
        page_name = page.get("name")
        page_token = page.get("access_token")

        # -----------------------------
        # 4 Create system user & system access token
        # -----------------------------
        # Note: Only for business accounts. Replace {BUSINESS_ID} with your business ID
        business_id = "<YOUR_BUSINESS_ID>"
        sys_user_url = f"https://graph.facebook.com/v21.0/{business_id}/system_users"
        # Try to create a new system user
        try:
            sys_user_resp = requests.post(
                sys_user_url,
                params={
                    "name": f"{current_user.username}_sys",
                    "role": "ADMIN",
                    "access_token": long_lived_token
                },
                timeout=10
            ).json()
            system_user_id = sys_user_resp.get("id")
        except Exception:
            system_user_id = None

        # -----------------------------
        # 5 Generate system user access token
        # -----------------------------
        if system_user_id:
            token_resp = requests.post(
                f"https://graph.facebook.com/v21.0/{system_user_id}/access_tokens",
                params={
                    "type": "ADMIN",
                    "business": business_id,
                    "app": FB_APP_ID,
                    "scope": "pages_manage_posts,pages_read_engagement,pages_show_list",
                    "access_token": long_lived_token
                },
                timeout=10
            ).json()
            system_token = token_resp.get("access_token")
        else:
            system_token = None

        # -----------------------------
        # 6 Save everything to DB
        # -----------------------------
        current_user.facebook_page_id = page_id
        current_user.facebook_page_token = page_token
        current_user.facebook_long_lived_token = long_lived_token
        db.session.commit()

        # -----------------------------
        # 7 Send tokens to Make.com
        # -----------------------------
        payload = {
            "user_id": current_user.id,
            "username": current_user.username,
            "page_id": page_id,
            "page_name": page_name,
            "page_access_token": page_token,
            "long_lived_user_token": long_lived_token,
            "system_user_id": system_user_id,
            "system_user_token": system_token
        }

        try:
            r = requests.post(MAKE_WEBHOOK_URL, json=payload, timeout=10)
            r.raise_for_status()
        except Exception as e:
            print("❌ Failed to send tokens to Make.com:", e)
            flash("Facebook connected, but failed to send tokens to Make.com.", "warning")
            return redirect(url_for("dashboard"))

        flash("Facebook Page connected successfully! Tokens sent to Make.com.", "success")
        return redirect(url_for("dashboard"))

    except requests.exceptions.RequestException as e:
        flash(f"Facebook connection error: {str(e)}", "danger")
        return redirect(url_for("dashboard"))


# -------------------- Facebook Page Selection --------------------
@app.route("/facebook/choose-page", methods=["GET"])
@login_required
def choose_facebook_page():
    pages = session.get("fb_pages_list")
    if not pages:
        flash("Facebook Pages list not found. Please reconnect.", "danger")
        return redirect(url_for("dashboard"))
    return render_template("choose_page.html", pages=pages)


@app.route("/facebook/save-page", methods=["POST"])
@login_required
def save_facebook_page():
    page_id = request.form.get("page_id")
    long_lived_user_token = session.get("fb_long_lived_token")

    if not page_id or not long_lived_user_token:
        flash("Invalid page selection. Please reconnect.", "danger")
        return redirect(url_for("dashboard"))

    # Get the page token from the corresponding hidden input
    page_token = request.form.get(f"page_token_{page_id}")
    if not page_token:
        flash("Page token not found. Please reconnect.", "danger")
        return redirect(url_for("dashboard"))

    # Save selected page to database
    current_user.facebook_page_id = page_id
    current_user.facebook_page_token = page_token
    current_user.facebook_long_lived_token = long_lived_user_token
    db.session.commit()

    # Send to Make.com
    payload = {
        "user_id": current_user.id,
        "long_lived_user_token": long_lived_user_token,
        "page_id": page_id,
        "page_access_token": page_token
    }

    try:
        r = requests.post(MAKE_WEBHOOK_URL, json=payload, timeout=10)
        r.raise_for_status()
    except Exception as e:
        print("❌ Failed to send tokens to Make.com:", e)
        flash("Facebook connected, but Make.com webhook failed.", "warning")
        return redirect(url_for("dashboard"))

    # Clear session pages
    session.pop("fb_pages_list", None)
    session.pop("fb_long_lived_token", None)

    flash("Facebook Page connected successfully!", "success")
    return redirect(url_for("dashboard"))

# -------------------- Change Facebook Page --------------------
@app.route("/facebook/change-page")
@login_required
def change_facebook_page():
    # Clear any previous selection from session
    session.pop("fb_pages_list", None)
    session.pop("fb_long_lived_token", None)

    # Redirect to OAuth flow again
    return redirect(url_for("connect_facebook"))

@app.route("/disconnect_facebook_page", methods=["POST"])
@login_required
def disconnect_facebook_page():
    # Remove Facebook info from current user
    current_user.facebook_page_id = None
    current_user.facebook_page_name = None
    # Save to DB
    db.session.commit()
    flash("Facebook page disconnected successfully!", "success")
    return redirect(url_for("dashboard"))
    
# ------------------- Facebook Insights --------------------
#-------------------insights--------------------
def get_page_insights(page_id, page_access_token):
    url = f"https://graph.facebook.com/v24.0/{page_id}/insights"
    params = {
        "metric": "page_follows,page_media_view,page_follows_country,page_follows_city",
        "period": "day",
        "access_token": page_access_token
    }
    try:
        response = requests.get(url, params=params, timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        return {"error": {"message": str(e)}}


@app.route("/page-insights")
@login_required
def page_insights_view():
    if not current_user.facebook_page_id or not current_user.facebook_page_token:
        return render_template("insights.html", page_insights={"error": {"message": "No Facebook page connected"}})

    data = get_page_insights(current_user.facebook_page_id, current_user.facebook_page_token)
    return render_template("insights.html", page_insights=data)



# ------------------- API Endpoint for AJAX / JSON --------------------
@app.route("/api/get_page_insights")
@login_required
def get_page_insights_route():
    """
    Return Facebook Page insights as JSON for AJAX calls.
    """
    if not current_user.facebook_page_id or not current_user.facebook_page_token:
        return jsonify({"error": {"message": "No Facebook page connected"}})

    data = get_page_insights(current_user.facebook_page_id, current_user.facebook_page_token)
    return jsonify(data)
    
    
# -------------------- Auth Routes --------------------
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")
        facebook_page = request.form.get("facebook_page")  # ✅ read from form

        if not username or not email or not password:
            flash("All fields are required.", "danger")
            return redirect(url_for("signup"))

        if User.query.filter_by(email=email).first():
            flash("Email already exists.", "danger")
            return redirect(url_for("signup"))

        if User.query.filter_by(username=username).first():
            flash("Username already taken.", "danger")
            return redirect(url_for("signup"))

        hashed_password = generate_password_hash(password, method="pbkdf2:sha256")
        user = User(username=username, email=email, password=hashed_password)
        db.session.add(user)
        db.session.commit()

        # --- Send signup data to Make.com ---
        try:
            requests.post(
                "https://hook.eu2.make.com/67oht2141ucgn7sjx4oysaj8ybxmhcan",
                json={
                    "username": user.username,
                    "user_id": user.id,
                    "page_name": facebook_page
                },
                timeout=10
            )
        except Exception as e:
            print("❌ Signup webhook error:", e)

        flash("Account created!", "success")
        return redirect(url_for("login"))

    return render_template("signup.html")

#-------------------- Login --------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid credentials.", "danger")
            return redirect(url_for("login"))
    return render_template("login.html")

#-------------------- Logout --------------------
@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("index"))

# -------------------- Password Recovery --------------------
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user:
            token = s.dumps(email, salt='password-reset')
            link = url_for('reset_password', token=token, _external=True)
            msg = Message("Password Reset Request", recipients=[email])
            msg.body = f"Click here to reset your password: {link}"
            mail.send(msg)
            flash('Password reset link sent to your email.', 'success')
        else:
            flash('Email not found.', 'danger')
        return redirect(url_for('login'))
    return render_template('forgot_password.html')

# -------------------- Reset Password --------------------
@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = s.loads(token, salt='password-reset', max_age=3600)
    except:
        flash('The reset link is invalid or has expired.', 'danger')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        new_password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user:
            user.set_password(new_password)
            db.session.commit()
            flash('Password has been reset. You can now log in.', 'success')
            return redirect(url_for('login'))
        flash('User not found.', 'danger')
        return redirect(url_for('login'))

    return render_template('reset_password.html')

# -------------------- Dashboard --------------------
@app.route('/dashboard')
@login_required
def dashboard():
    # Only block certain features, don't block the entire page
    return render_template('dashboard_base.html')



# -------------------------
# Profile Route
# -------------------------
@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html')

# -------------------------
# Settings Route
# -------------------------
@app.route('/settings')
@login_required
def settings():
    return render_template('settings.html')

# -------------------------
# Change Password Route
# -------------------------
@app.route('/change-password', methods=['POST'])
@login_required
def change_password():
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')

    # TODO: Implement your password validation logic
    if current_user.check_password(current_password):
        current_user.set_password(new_password)
        flash('Password updated successfully!', 'success')
    else:
        flash('Current password is incorrect.', 'danger')

    return redirect(url_for('settings'))



# -------------------- Subscription Management --------------------
def create_subscription(user, package_name, days, amount, interval="monthly"):
    now = datetime.now(LOCAL_TZ)
    end_date = now + timedelta(days=days)
    sub = Subscription(
        user_id=user.id,
        type=package_name,
        start_date=now,
        end_date=end_date,
        status="active",
        amount_paid=amount,
        payment_interval=interval
    )
    db.session.add(sub)
    db.session.commit()

    # Notify Make.com with package name, number of days, and amount paid (as requested)
    try:
        requests.post(WEBHOOK_SUBSCRIPTION, json={
            "user_id": user.id,
            "subscription_type": package_name,
            "subscription_days": days,
            "subscription_start_date": now.strftime("%Y-%m-%d %H:%M:%S"),
            "subscription_end_date": end_date.strftime("%Y-%m-%d %H:%M:%S"),
            "amount_paid": amount,
            "username": user.username,
            "status": "success",
            "payment_interval": interval
        }, timeout=10)
    except Exception as e:
        print("❌ Failed to notify Make.com:", e)

# -------------------- Ecocash Payment Integration --------------------
def attempt_ecocash_payment(phone_number: str, amount: float, short_code: str = "36174", timeout: int = 15):
    """
    Make a payment request to Ecocash USSD-push endpoint.
    Returns (True, response_text_or_json) on success, (False, response_text_or_json) on failure.
    """
    payload = {
        "msisdn": phone_number,
        "short_code": short_code,
        "amount": amount
    }
    try:
        resp = requests.post(ECOCASH_API_URL, json=payload, timeout=timeout)
        text = None
        try:
            text = resp.json()
        except Exception:
            text = resp.text

        # Heuristic success checks: HTTP 200 and either JSON status or "successfully" in text
        if resp.status_code == 200:
            # if JSON with status field
            if isinstance(text, dict):
                # common field name might be 'status' with 'SUCCESS' or 'success'
                status_val = text.get("status") or text.get("Status") or text.get("message")
                if status_val and ("success" in str(status_val).lower()):
                    return True, text
                # sometimes API returns {"response":"success"} etc.
                flattened = " ".join([str(v) for v in text.values()])
                if "success" in flattened.lower() or "successfully" in flattened.lower():
                    return True, text
            else:
                # text response
                if "success" in str(text).lower() or "successfully" in str(text).lower():
                    return True, text
        # Not a success
        return False, text
    except requests.exceptions.RequestException as e:
        return False, str(e)
# -------------------- Package Routes (each has own route) --------------------

@app.route("/packages")
@login_required
def packages():
    return render_template("packages.html")

@app.route('/pricing')
@login_required
def pricing():
    """
    Render the pricing page.
    Accessible only to authenticated users.
    Users without active subscription will see options to subscribe.
    """
    return render_template('pricing.html', current_user=current_user)


# --------------- Package Subscription Routes --------------------
# Startup
@app.route("/subscribe/startup", methods=["POST"])
@login_required
def subscribe_startup():
    phone_number = request.form.get("phone")
    interval = request.form.get("billing_period", "monthly")  # 'monthly' or 'annual'
    if not phone_number:
        flash("Please enter Ecocash number for payment.", "danger")
        return redirect(url_for("dashboard"))

    # prices (local currency values)
    prices = {"monthly": 1, "annual": 1}  # M50 / M500
    days = 30 if interval == "monthly" else 365
    amount = prices.get(interval, prices["monthly"])

    # Call Ecocash API (USSD push)
    success, resp = attempt_ecocash_payment(phone_number=phone_number, amount=amount)
    if success:
        create_subscription(current_user, "Startup", days, amount, interval=interval)
        flash(f"Startup Package subscribed successfully ({interval})!", "success")
    else:
        # Log resp for debugging (server console) and notify user
        print("Ecocash startup payment failed:", resp)
        flash("Payment failed. Please try again or contact support.", "danger")
    return redirect(url_for("dashboard"))

# Growth
@app.route("/subscribe/growth", methods=["POST"])
@login_required
def subscribe_growth():
    phone_number = request.form.get("phone")
    interval = request.form.get("billing_period", "monthly")
    if not phone_number:
        flash("Please enter Ecocash number for payment.", "danger")
        return redirect(url_for("dashboard"))

    prices = {"monthly": 1, "annual": 1}  # M100 / M1000
    days = 30 if interval == "monthly" else 365
    amount = prices.get(interval, prices["monthly"])

    success, resp = attempt_ecocash_payment(phone_number=phone_number, amount=amount)
    if success:
        create_subscription(current_user, "Growth", days, amount, interval=interval)
        flash(f"Growth Package subscribed successfully ({interval})!", "success")
    else:
        print("Ecocash growth payment failed:", resp)
        flash("Payment failed. Please try again or contact support.", "danger")
    return redirect(url_for("dashboard"))

# Pro
@app.route("/subscribe/pro", methods=["POST"])
@login_required
def subscribe_pro():
    phone_number = request.form.get("phone")
    interval = request.form.get("billing_period", "monthly")
    if not phone_number:
        flash("Please enter Ecocash number for payment.", "danger")
        return redirect(url_for("dashboard"))

    prices = {"monthly": 1, "annual": 1}  # M230 / M2300
    days = 30 if interval == "monthly" else 365
    amount = prices.get(interval, prices["monthly"])

    success, resp = attempt_ecocash_payment(phone_number=phone_number, amount=amount)
    if success:
        create_subscription(current_user, "Pro", days, amount, interval=interval)
        flash(f"Pro Package subscribed successfully ({interval})!", "success")
    else:
        print("Ecocash pro payment failed:", resp)
        flash("Payment failed. Please try again or contact support.", "danger")
    return redirect(url_for("dashboard"))

# Free trial (no payment)
@app.route("/subscribe/trial", methods=["GET"])
@login_required
def subscribe_trial():
    if current_user.used_trial:
        flash("You have already used your free trial.", "danger")
        return redirect(url_for("dashboard"))
    create_subscription(current_user, "Free Trial", 14, 0, interval="trial")
    current_user.used_trial = True
    db.session.commit()
    flash("Free Trial activated! Enjoy 14 days of access.", "success")
    return redirect(url_for("dashboard"))



# -------------------- Content Management --------------------

@app.route("/webhook/new_content", methods=["POST"])
def webhook_new_content():
    data = request.get_json() or request.form
    if not data:
        return jsonify({"status": "error", "message": "No JSON received"}), 400

    user_id = data.get("user_id")
    text = data.get("text")

    if not user_id or not text:
        return jsonify({"status": "error", "message": "Missing user_id or text"}), 400

    user = User.query.filter_by(id=user_id).first()
    if not user:
        return jsonify({"status": "error", "message": "User not found"}), 404

    content = Content(text=text, status="pending", user_id=user.id)
    db.session.add(content)
    db.session.commit()

    return jsonify({"status": "success", "message": "Content added to pending"}), 201
    
# -------------------- File Upload --------------------
@app.route("/upload", methods=["GET", "POST"])
@login_required
@subscription_required
def upload_file():
    if request.method == "POST":
        uploaded_file = request.files.get("file")
        category = request.form.get("category", "general")
        if uploaded_file and uploaded_file.filename:
            # Read bytes first (so we can both save and send them)
            file_bytes = uploaded_file.read()
            filename = secure_filename(uploaded_file.filename)
            path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            # Save to disk
            with open(path, "wb") as f:
                f.write(file_bytes)
            # Record in DB
            doc = Document(filename=filename, category=category, user_id=current_user.id)
            db.session.add(doc)
            db.session.commit()
            flash("File uploaded successfully.", "success")

            # Send file to webhook (base64 encoded)
            try:
                facebook_page = request.form.get("facebook_page")

                files = {
                    "file": (filename, file_bytes, uploaded_file.content_type)
                }

                data = {
                    "filename": filename,
                    "user_id": current_user.id,
                    "facebook_page_name": facebook_page
                }

                response = requests.post(WEBHOOK_SEND_FILE, files=files, data=data, timeout=10)
                response.raise_for_status()

            except Exception as e:
                print("❌ Upload webhook error:", e)
                flash("File uploaded but webhook notification failed.", "warning")

            return redirect(url_for("upload_file"))
    return render_template("upload_file.html")

# -------------------- Content Views --------------------
@app.route("/pending")
@login_required
@subscription_required
def pending_content():
    # Use local timezone
    now = datetime.now(LOCAL_TZ)
    month = int(request.args.get("month", now.month))
    year = int(request.args.get("year", now.year))

    # Days in the month
    days_in_month = calendar.monthrange(year, month)[1]

    # Previous / next month navigation
    prev_month = month - 1 if month > 1 else 12
    prev_year = year if month > 1 else year - 1
    next_month = month + 1 if month < 12 else 1
    next_year = year if month < 12 else year + 1

    # Fetch pending content for current user
    contents = Content.query.filter_by(status="pending", user_id=current_user.id).all()

    return render_template(
        "pending_content.html",
        contents=contents,
        month=month,
        year=year,
        days_in_month=days_in_month,
        prev_month=prev_month,
        prev_year=prev_year,
        next_month=next_month,
        next_year=next_year,
        month_name=calendar.month_name[month],
        calendar=calendar,  # pass calendar module
        current_day=now.day,
        current_month=now.month,
        current_year=now.year
    )


@app.route("/approved")
@login_required
@subscription_required
def approved_content():
    # Use local timezone
    now = datetime.now(LOCAL_TZ)
    month = request.args.get("month", now.month, type=int)
    year = request.args.get("year", now.year, type=int)

    # Navigation
    prev_month = month - 1 if month > 1 else 12
    prev_year = year if month > 1 else year - 1
    next_month = month + 1 if month < 12 else 1
    next_year = year if month < 12 else year + 1

    # Days in month
    days_in_month = calendar.monthrange(year, month)[1]

    # Current day info
    current_day, current_month, current_year = now.day, now.month, now.year

    # Fetch approved content for current user
    contents = Content.query.filter_by(status="approved", user_id=current_user.id).all()

    return render_template(
        "approved_content.html",
        contents=contents,
        month=month,
        year=year,
        prev_month=prev_month,
        prev_year=prev_year,
        next_month=next_month,
        next_year=next_year,
        days_in_month=days_in_month,
        current_day=current_day,
        current_month=current_month,
        current_year=current_year,
        month_name=calendar.month_name[month],
        calendar=calendar  # pass calendar module
    )


    
@app.route("/posted")
@login_required
@subscription_required
def posted_content():
    contents = Content.query.filter_by(status="posted", user_id=current_user.id).all()
    return render_template("posted_content.html", contents=contents)
    
    
@app.route("/content/schedule/<content_id>", methods=["POST"])
@login_required
@subscription_required
def schedule_content(content_id):
    """
    Standalone route to schedule pending content.
    Only updates scheduled_time; content text is untouched.
    """
    content = Content.query.get_or_404(content_id)

    # Only allow scheduling if content is pending and belongs to current user
    if content.user_id != current_user.id or content.status != "pending":
        flash("You cannot schedule this content.", "danger")
        return redirect(url_for("pending_content"))

    scheduled_time_str = request.form.get("scheduled_time")
    if scheduled_time_str:
        try:
            # Parse naive datetime from input
            dt_naive = datetime.strptime(scheduled_time_str, "%Y-%m-%dT%H:%M")
            # Localize to your server timezone
            content.scheduled_time = LOCAL_TZ.localize(dt_naive)
        except ValueError:
            flash("Invalid date/time format. Use YYYY-MM-DDTHH:MM", "danger")
            return redirect(url_for("pending_content"))

    db.session.commit()
    flash("Content scheduled successfully!", "success")
    return redirect(url_for("pending_content"))


@app.route("/content/approve/<content_id>", methods=["POST"])
@login_required
@subscription_required
def approve_content(content_id):
    content = Content.query.get_or_404(content_id)
    if content.user_id != current_user.id or content.status != "pending":
        flash("You cannot approve this content.", "danger")
        return redirect(url_for("pending_content"))

    content.status = "approved"
    content.approved_at = datetime.now(LOCAL_TZ)
    db.session.commit()
    flash("Content approved successfully!", "success")
    return redirect(url_for("pending_content"))

@app.route("/content/reject/<content_id>", methods=["POST"])
@login_required
@subscription_required
def reject_content(content_id):
    content = Content.query.get_or_404(content_id)
    if content.user_id != current_user.id or content.status != "pending":
        flash("You cannot reject this content.", "danger")
        return redirect(url_for("pending_content"))

    content.status = "rejected"
    db.session.commit()
    flash("Content rejected successfully!", "success")
    return redirect(url_for("pending_content"))



scheduler.add_job(post_scheduled_content, "interval", minutes=1)

scheduler.start()

if __name__ == "__main__":
    if not os.path.exists("uploads"):
        os.makedirs("uploads")
    app.run(debug=True)

