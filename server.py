import secrets
import base64
import json

from flask import Flask, request, render_template, make_response, redirect, url_for

app = Flask(__name__)

cookies = []
messages = []

def generate_cookie(user, secret="secret_key"):
    token = secrets.token_urlsafe(32)

    cookie = {"user": user, "value": token}

    cookies.append(cookie)
    return cookie


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        if (request.form['username'] == 'admin' and request.form['password'] == 'admin') or\
            (request.form['username'] == 'user1' and request.form['password'] == 'password') or\
            (request.form['username'] == 'user2' and request.form['password'] == 'password'):
            resp = make_response(redirect(url_for('home')))

            plain_cookie = generate_cookie(request.form['username'])

            resp.set_cookie('plain_cookie', base64.b64encode(json.dumps(plain_cookie).encode('utf-8')))
            resp.set_cookie('secure_cookie', base64.b64encode(json.dumps(plain_cookie).encode('utf-8')), secure=True)
            resp.set_cookie('samesite_cookie', base64.b64encode(json.dumps(plain_cookie).encode('utf-8')), samesite="Strict")
            resp.set_cookie('httponly_cookie', base64.b64encode(json.dumps(plain_cookie).encode('utf-8')), httponly=True)

            resp.set_cookie('good_cookie', base64.b64encode(json.dumps(plain_cookie).encode('utf-8')), httponly=True, secure=True, samesite="Strict")
            return resp

        else:
            error = 'Invalid Credentials. Please try again.'
    return render_template('login.html', error=error)

@app.route('/logoff')
def logout():

    resp = make_response(redirect(url_for('login')))

    resp.set_cookie('plain_cookie', '', expires=0)
    resp.set_cookie('secure_cookie', '', expires=0)
    resp.set_cookie('samesite_cookie', '', expires=0)
    resp.set_cookie('httponly_cookie', '', expires=0)
    resp.set_cookie('good_cookie', '', expires=0)

    return resp

@app.route('/post_message')
def post_message():
    error = None
    global messages

    cookie = request.cookies.get('plain_cookie')
    cookie_val = json.loads(base64.b64decode(cookie).decode('utf-8'))

    message = request.args.get('message')

    if message is not None and len(message) > 0:
        messages.append((cookie_val["user"], message))

    return redirect(url_for('home'))


@app.route('/')
def home():
    error = None
    global messages

    cookie = request.cookies.get('plain_cookie')
    if cookie is None:
        return render_template('home_logoff.html', error=error)

    cookie_val = json.loads(base64.b64decode(cookie).decode('utf-8'))
    user = cookie_val["user"]

    nm = """
<html>
  <head>
    <title>Flask Intro - Home</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link href="static/bootstrap.min.css" rel="stylesheet" media="screen">
  </head>
  <body>
    <div class="container">
      <h1>Welcome!</h1>
      <br>
      <form action="/logoff" method="get">
        <input type="submit" value="Log out" name="logoff" id="logoff" />
      </form>
      <br>
      <form action="/post_message" method="get">
        <label for="message">Message: </label>
        <input type="text" id="message" name="message"><br><br>
        <input type="submit" value="Submit">
      </form>
    """

    for msg in messages:
        if user == 'admin':
            nm += '<li class="collection-item">%s: %s</li>\n' % (msg[0], msg[1])
        elif user == msg[0]:
            nm += '<li class="collection-item">%s: %s</li>\n' % (msg[0], msg[1])

    nm += "    </div>\n  </body>\n</html>"

    return nm
