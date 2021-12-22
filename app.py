import os.path
import werkzeug.utils
from flask import Flask, request, session, url_for, redirect
import flask

app = Flask(__name__)
upload_folder = "uploads"
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "pdf", "txt"}


if app.secret_key is None:
    app.secret_key = os.urandom(20)


@app.route('/logedin')
def logedin():
    if 'username' in session:
        return f'Logged in as {session["username"]}'
    return 'You are not logged in'

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        session['username'] = request.form['username']
        return redirect(url_for('logedin'))
    return '''
        <form method="post">
            <p><input type=text name=username>
            <p><input type=submit value=Login>
        </form>
    '''

@app.route('/logout')
def logout():
    # remove the username from the session if it's there
    session.pop('username', None)
    return redirect(url_for('logedin'))


def allowed(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route("/file_upload", methods=["POST", "GET"])
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


@app.route("/json_site")
def json_site():
    d = {"Tisch": [1, 2, 3, 4], "Stuhl": [5, 6, 7, 8]}
    return d


@app.route('/', defaults={"path": ""})
@app.route("/<path:path>")
def index(path):  # put application's code here
    return 'Welcome to the title page'


@app.route('/hello/<string:name>')
def hello(name):  # put application's code here
    return 'Hello ' + name + "!"


@app.route('/rechne/<int:faktor>mal2')
def mal2(faktor):
    return "{} * 2 = {}".format(faktor, faktor * 2)


@app.route('/login_form')
def login_form():
    return flask.render_template("index.html", fantasie="Begrüßungs Formular")


@app.route('/login_form2')
def login_form2():
    return flask.make_response(flask.render_template("index.html"))


@app.route('/login2', methods=["POST", "GET"])
def login2():
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


if __name__ == '__main__':
    app.run(port=1337, debug=True)
