import os.path
import pathlib
from flask import Flask, session, redirect, url_for, request, abort
from google.oauth2 import id_token
from google.auth.transport import requests
from google_auth_oauthlib.flow import Flow

app = Flask("Google Login App")
app.secret_key = "webdads2u.com"
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

GOOGLE_CLIENT_ID = "835417066697-ht23frqqbmb5lj3u600g5ost2biptcdf.apps.googleusercontent.com"
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret.json")
flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile",
            "https://www.googleapis.com/auth/userinfo.email",
            "openid"],
    redirect_uri="http://127.0.0.1:5000/callback"
)

def login_required(function):
    def wrapper(*args, **kwargs):
        if "google_id" not in session:
            return abort(401)  # Authorization required
        return function(*args, **kwargs)
    return wrapper

@app.route("/login")
def login():
    authorization_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(authorization_url)

@app.route("/callback")
def callback():
    flow.fetch_token(authorization_response=request.url)

    # Ensure state matches the one set in session
    if not session["state"] == request.args["state"]:
        abort(500)  # State does not match, potential CSRF attack

    credentials = flow.credentials
    request_session = requests.Request()

    # Verify the token
    id_info = id_token.verify_oauth2_token(
        id_token=credentials._id_token,
        request=request_session,
        audience=GOOGLE_CLIENT_ID
    )

    # Store the user information in session
    session["google_id"] = id_info.get("sub")
    session["name"] = id_info.get("name")

    return redirect("/")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

@app.route("/")
def index():
    return "Hello World <a href='/login'><button>Login</button></a>"

@app.route("/protected_area")
@login_required
def protected_area():
    return f"Protected Area! Welcome {session['name']} <a href='/logout'><button>Logout</button></a>"

if __name__ == '__main__':
    app.run(debug=True)
