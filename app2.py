import os
import werkzeug.utils
from flask import Flask, request, session, url_for, redirect, jsonify, Blueprint
import flask
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity, set_access_cookies, unset_jwt_cookies,
    create_refresh_token, set_refresh_cookies, get_jwt, get_csrf_token
)

app = Flask(__name__)
upload_folder = "uploads"
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "pdf", "txt"}

page1 = Blueprint('page1', __name__, template_folder='templates', url_prefix='/page1')

app.config["JWT_SECRET_KEY"] = os.urandom(20)
app.config["JWT_TOKEN_LOCATION"] = "cookies"
app.config["JWT_COOKIE_SECURE"] = True
app.config["JWT_COOKIE_CSRF_PROTECT"] = True
jwt = JWTManager(app)

if app.secret_key is None:
    app.secret_key = os.urandom(20)


@page1.route("/login_jwt", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return flask.render_template("login.html")
    username = request.form.get("username", None)
    password = request.form.get("password", None)
    if username != "my-user" or password != "my-key":
        return jsonify({"msg": "Bad username or password"}), 401

    access_token = create_access_token(identity=username)
    refresh_token = create_refresh_token(identity=username)
    resp = jsonify(login=True)
    set_access_cookies(resp, access_token)
    set_refresh_cookies(resp, refresh_token)
    return resp

@page1.route("/refresh_jwt")
@jwt_required(refresh=True)
def refresh_jwt():
    user = get_jwt_identity()
    access_token = create_access_token(identity=user)
    resp = jsonify(refresh=True)
    set_access_cookies(resp, access_token)
    return resp

def check_csrf_header(request):
    csrf_token = get_jwt()["csrf"]
    csrf_header = request.headers.get("X-CSRF-TOKEN")
    return csrf_header == csrf_token


@page1.route("/protected_jwt", methods=["GET"])
@jwt_required()
def protected():
    # Access the identity of the current user with get_jwt_identity
    current_user = get_jwt_identity()
    jwt_token = get_jwt()
    csrf_token = jwt_token["csrf"]
    csrf_header = request.headers.get("X-CSRF-TOKEN")
    csrf_header_set = check_csrf_header(request)
    return jsonify({"logged_in_as": current_user, "jwt_csrf_token":csrf_token, "header_csrf_token": csrf_header,
                    "csrf_authenticated": csrf_header_set}), 200

@page1.route("/logout_jwt")
def logout_jwt():
    resp = jsonify({"logout": True})
    unset_jwt_cookies(resp)
    return resp


@page1.route('/logedin_session')
def logedin_session():
    if 'username' in session:
        return f'Logged in as {session["username"]}'
    return 'You are not logged in'

@page1.route('/login_session', methods=['GET', 'POST'])
def login_session():
    if request.method == 'POST':
        session['username'] = request.form['username']
        return redirect(url_for('logedin_session'))
    return '''
        <form method="post">
            <p><input type=text name=username>
            <p><input type=submit value=Login>
        </form>
    '''

@page1.route('/logout_session')
def logout_session():
    # remove the username from the session if it's there
    session.pop('username', None)
    return redirect(url_for('logedin_session'))


def allowed(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


@page1.route("/file_upload", methods=["POST", "GET"])
def file_upload():
    if request.method == "POST":
        if "file" not in request.files:
            return flask.redirect(request.url)
        file = request.files["file"]
        if file.filename == "" or not allowed(file.filename):
            return flask.redirect(request.url)
        filename = werkzeug.utils.secure_filename(file.filename)
        file.save(os.path.join(upload_folder, filename))
    return flask.render_template("fileUpload.html")


@page1.route("/json_site")
def json_site():
    d = {"Tisch": [1, 2, 3, 4], "Stuhl": [5, 6, 7, 8]}
    return d


@page1.route('/', defaults={"path": ""})
@page1.route("/<path:path>")
def index(path):  # put application's code here
    return 'Welcome to the title page'


@page1.route('/hello/<string:name>')
def hello(name):  # put application's code here
    return 'Hello ' + name + "!"


@page1.route('/rechne/<int:faktor>mal2')
def mal2(faktor):
    return "{} * 2 = {}".format(faktor, faktor * 2)


@page1.route('/login_form')
def login_form():
    return flask.render_template("index.html", fantasie="Begrüßungs Formular")


@page1.route('/login_form2')
def login_form2():
    return flask.make_response(flask.render_template("index.html"))


@page1.route('/login_cookie', methods=["POST", "GET"])
def login_cookie():
    cookie_username = request.cookies.get("username")
    if cookie_username is not None:
        return f"Hello from the cookie {cookie_username}"
    resp = flask.make_response()
    if request.method == "POST":
        name = request.form["login_name"]
        resp.set_cookie("username", name)
    else:
        name = "Namenloser"
    resp.set_data(f"Hallo {name}!")
    return resp


app.register_blueprint(page1)

if __name__ == '__main__':
    app.run(port=1337, debug=True)
