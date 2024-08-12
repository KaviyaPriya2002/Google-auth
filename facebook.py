import os
import requests
from flask import Flask, session, redirect, url_for, request, abort

app = Flask("Facebook Login App")
app.secret_key = "0d01ad09d436d35eb76eb9b0e0399be1"
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

FACEBOOK_CLIENT_ID = "420455437384689"
FACEBOOK_CLIENT_SECRET = "0d01ad09d436d35eb76eb9b0e0399be1"
FACEBOOK_REDIRECT_URI = "http://127.0.0.1:5000/callback/facebook"


def login_required(function):
    def wrapper(*args, **kwargs):
        if "facebook_id" not in session:
            return abort(401)  # Authorization required
        return function(*args, **kwargs)

    return wrapper


@app.route("/login")
def login():
    facebook_auth_url = (
        'https://www.facebook.com/v11.0/dialog/oauth?'
        f'client_id={FACEBOOK_CLIENT_ID}&'
        f'redirect_uri={FACEBOOK_REDIRECT_URI}&'
        'scope=email'
    )
    return redirect(facebook_auth_url)


@app.route("/callback/facebook")
def callback():
    code = request.args.get('code')
    token_url = 'https://graph.facebook.com/v11.0/oauth/access_token'
    token_params = {
        'client_id': FACEBOOK_CLIENT_ID,
        'redirect_uri': FACEBOOK_REDIRECT_URI,
        'client_secret': FACEBOOK_CLIENT_SECRET,
        'code': code
    }
    token_response = requests.get(token_url, params=token_params)
    token_json = token_response.json()
    access_token = token_json.get('access_token')

    userinfo_url = 'https://graph.facebook.com/me?fields=id,name,email'
    userinfo_response = requests.get(userinfo_url, params={'access_token': access_token})
    userinfo = userinfo_response.json()

    # Store the user information in session
    session["facebook_id"] = userinfo.get("id")
    session["name"] = userinfo.get("name")

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
