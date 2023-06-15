import os
import datetime

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required

# Configure application
app = Flask(__name__)

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///legaLimit.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
def index():

    return render_template("index.html")


@app.route("/federal", methods=["GET", "POST"])
@login_required
def federal():

    return render_template("federal.html")


@app.route("/portfolio")
@login_required
def portfolio():
    searchPortfolio = db.execute("SELECT * FROM searchPortfolio WHERE user_id = ?", session["user_id"])
    name = db.execute("SELECT username FROM users WHERE id = ?", session["user_id"])
    return render_template("portfolio.html", name=name, searchPortfolio=searchPortfolio)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        flash("You have logged in successfully, " + request.form.get("username"))

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    """Log user out"""

    session.clear()

    flash("You have logged out successfully.")
    return render_template("index.html")


@app.route("/local", methods=["GET", "POST"])
@login_required
def local():

    return render_template("local.html")

@app.route("/register", methods=["GET", "POST"])
def register():

    session.clear()

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        users = db.execute("SELECT * FROM users WHERE username = ?", username)
        userPass = db.execute("SELECT * FROM users")

        if not username:
            return apology("must provide username", 400)

        elif not password:
            return apology("must provide password", 400)

        elif password != confirmation:
            return apology("must confirm password", 400)

        if users:
            return apology("sorry, username taken", 403)

        for row in userPass:
            if check_password_hash(userPass[0]["hash"], confirmation) == True:
                return apology("Sorry, password taken", 403)

        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, generate_password_hash(confirmation))
        regRow = db.execute("SELECT id FROM users WHERE username = ?", username)
        session["user_id"] = regRow[0]["id"]
        flash("Your account has been created successfully, " + username)
        return redirect("/")

    else:
        return render_template("register.html")


@app.route("/state", methods=["GET", "POST"])
@login_required
def state():

    return render_template("state.html")


@app.route("/updatePass", methods=["GET", "POST"])
@login_required
def updatePass():
    password = request.form.get("password")
    passConfirm = request.form.get("passConfirm")
    newPass = request.form.get("newPass")
    newPassConfirm = request.form.get("newPassConfirm")

    users = db.execute("SELECT * FROM users")

    if request.method == "POST":

        if not password:
            return apology("must provide password", 400)

        elif not passConfirm:
            return apology("must confirm password", 400)

        elif not newPass:
            return apology("must provide new password", 400)

        elif not newPassConfirm:
            return apology("must confirm new password", 400)

        elif password != passConfirm:
            return apology("must confirm password", 400)

        elif newPass != newPassConfirm:
            return apology("must confirm new password", 400)

        for row in users:
            if check_password_hash(users[0]["hash"], newPass):
                return apology("password already taken", 400)

        db.execute("UPDATE users SET hash = ? WHERE id = ?", generate_password_hash(newPass), session["user_id"])
        flash("Your new password has been set.")
        return redirect("/")

    else:
        return render_template("updatePass.html")

@app.route("/submit", methods=["GET", "POST"])
@login_required
def submit():
    if request.method == "POST":
        statuteText = request.form.get("statuteText")

        if not statuteText:
            return apology("Please paste the statute into the text field", 400)

        level = request.form.get("level")

        if not level:
            return apology("Please select level of governance", 400)

        stateName = request.form.get("stateName")
        cityName = request.form.get("cityName")
        statute = request.form.get("statute")

        if not statute:
            return apology("Please enter the statute identifier", 400)

        url = request.form.get("url")

        if not url:
            return apology("Please enter url of statute", 400)

        flagNote = request.form.get("flagNote")

        if not flagNote:
            return apology("Please enter flag note for statute", 400)

        db.execute(
            "INSERT INTO searchPortfolio (user_id, level, stateName, cityName, statute, url, reason, statuteCopy) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", session["user_id"], level, stateName, cityName, statute, url, flagNote, statuteText)

        return redirect("/portfolio")

    else:
        return render_template("submit.html")

@app.route("/delete", methods=["POST"])
@login_required
def delete():

    id = request.form.get("id")

    if id:
        db.execute("DELETE FROM searchPortfolio WHERE id = ?", id)

    flash("Record deleted successfully")

    return redirect("/portfolio")

@app.route("/fullText", methods=["POST"])
@login_required
def fullText():

    id = request.form.get("id")
    statCopy = db.execute("SELECT * FROM searchPortfolio WHERE id = ?", id)

    return render_template("fullText.html", statCopy=statCopy)

@app.route("/edit", methods=["POST"])
@login_required
def edit():

    if request.method == "POST":
        id = request.form.get("id")
        editId = db.execute("SELECT * FROM searchPortfolio WHERE id = ?", id)
        return render_template("edit.html", editId=editId)

@app.route("/replace", methods=["POST"])
def replace():

    id = request.form.get("id")
    statuteText = request.form.get("statuteText")
    level = request.form.get("level")
    stateName = request.form.get("stateName")
    cityName = request.form.get("cityName")
    statute = request.form.get("statute")
    url = request.form.get("url")
    flagNote = request.form.get("flagNote")

    db.execute(
        "UPDATE searchPortfolio SET level = ?, stateName = ?, cityName = ?, statute = ?, url = ?, reason = ?, statuteCopy = ? WHERE id = ?", level, stateName, cityName, statute, url, flagNote, statuteText, id)
    flash("Record edited successfully")
    return redirect("/portfolio")