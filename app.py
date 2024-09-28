import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    stocks = db.execute(
        "SELECT symbol, SUM(shares) FROM portfolios GROUP BY symbol HAVING id = ?", session["user_id"])
    cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
    cash = cash[0]["cash"]
    currentPrice = []
    total = 0.0
    for stock in stocks:
        info = lookup(stock["symbol"])
        currentPrice.append(info["price"])
        total += info["price"] * stock["SUM(shares)"]
    total += cash
    cash = usd(cash)
    total = usd(total)
    return render_template("index.html", stocks=stocks, currentPrice=currentPrice, total=total, cash=cash)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")
        if not symbol:
            return apology("Enter symbol")
        try:
            shares = int(shares)
        except:
            return apology("Not an integer")
        if shares < 1:
            return apology("Enter a positive number of shares")
        info = lookup(symbol)
        time = datetime.now().strftime("%B %d, %Y %H:%M:%S")
        if not info:
            return apology("Invalid symbol")
        cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
        cash = cash[0]["cash"]
        if cash < shares * info["price"]:
            return apology("Not enough cash")

        # "Purchase" stocks
        db.execute("INSERT INTO portfolios (id, symbol, shares, price, time) VALUES (?, ?, ?, ?, ?)",
                   session["user_id"], symbol, shares, info["price"], time)

        # Change user cash value
        cash -= shares * info["price"]
        db.execute("UPDATE users SET cash = ? WHERE id = ?", cash, session["user_id"])

        return redirect("/")
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    history = db.execute("SELECT * FROM portfolios WHERE id = ?", session["user_id"])
    return render_template("history.html", history=history)


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
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":
        symbol = request.form.get("symbol")
        info = lookup(symbol)
        if not info:
            return apology("Invalid symbol")
        return render_template("quoted.html", info=info)
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        if not username or not password or not confirmation:
            return apology("Missing entry")
        if password != confirmation:
            return apology("Passwords do not match")
        hash = generate_password_hash(password)
        try:
            db.execute("INSERT INTO users (username, hash) VALUES(?, ?)", username, hash)
        except:
            return apology("Username exists")
        return redirect("/login")
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "POST":
        symbol = request.form.get("symbol")
        if not symbol:
            return apology("Select a stock to sell")
        shares = request.form.get("shares")
        try:
            shares = int(shares)
        except:
            return apology("Not an integer")
        if shares < 1:
            return apology("Enter a positive number of shares")
        sharesOwned = db.execute("SELECT SUM(shares) FROM portfolios GROUP BY symbol HAVING id = ? AND symbol = ?",
                                 session["user_id"], symbol)[0]["SUM(shares)"]
        if sharesOwned < shares:
            return apology("Not enough shares")
        info = lookup(symbol)
        time = datetime.now().strftime("%B %d, %Y %H:%M:%S")
        sold = info["price"] * shares
        oldCash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]
        newCash = oldCash + sold
        db.execute("UPDATE users SET cash = ? WHERE id = ?", newCash, session["user_id"])

        shares = shares * -1
        db.execute("INSERT INTO portfolios (id, symbol, shares, price, time) VALUES (?, ?, ?, ?, ?)",
                   session["user_id"], symbol, shares, info["price"], time)

        return redirect("/")
    else:
        stocks = db.execute(
            "SELECT symbol FROM portfolios GROUP BY symbol HAVING id = ? AND SUM(shares) <> 0", session["user_id"])
        return render_template("sell.html", stocks=stocks)


@app.route("/change", methods=["GET", "POST"])
@login_required
def change():
    """Change user password"""
    if request.method == "POST":
        oldPassword = request.form.get("oldPassword")
        newPassword = request.form.get("newPassword")
        confirmation = request.form.get("confirmation")
        if not oldPassword or not newPassword or not confirmation:
            return apology("Missing entry")
        rows = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])
        if not check_password_hash(rows[0]["hash"], oldPassword):
            return apology("Incorrect password")
        if newPassword != confirmation:
            return apology("New password and confirmation don't match")
        hash = generate_password_hash(newPassword)
        db.execute("UPDATE users SET hash = ? WHERE id = ?", hash, session["user_id"])

        session.clear()
        return redirect("/")
    else:
        return render_template("change.html")
