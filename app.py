import requests
import mysql.connector
from flask import Flask, render_template, redirect, url_for, flash, request
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
from flask import session
import os

load_dotenv()

def get_db():
    con = mysql.connector.connect(
        host=os.getenv("DB_HOST"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        database=os.getenv("DB_DATABASE")
    )
    cursor = con.cursor()
    return con, cursor

api_key = os.getenv("API_KEY")

url = "https://api.api-ninjas.com/v1/quotes"
headers = {"X-Api-Key": api_key}

def get_quote():
    response = requests.get(url, headers=headers)
    data = response.json()
    if isinstance(data, list) and len(data) > 0:
        return data[0]['quote'], data[0]['author'], data[0]['category']
    return "No quote found", "Unknown", "Unknown"

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")

@app.route('/', methods=["GET", "POST"])
def register():
    if request.method == 'POST':
        name = request.form.get('fname')
        email = request.form.get('email')
        password = generate_password_hash(request.form.get('password'))

        con, cursor = get_db()

        cursor.execute("SELECT id FROMusers WHERE email=%s", (email,))
        if cursor.fetchone():
            flash("User already exists")
            cursor.close()
            con.close()
            return redirect(url_for("register"))

        cursor.execute(
            "INSERT INTO users (name, email, password) VALUES (%s, %s, %s)",
            (name, email, password)
        )
        con.commit()

        cursor.close()
        con.close()

        flash("Registration Successful")
        return redirect('/login')

    return render_template('register.html')

@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        con, cursor = get_db()

        cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
        user = cursor.fetchone()

        cursor.close()
        con.close()

        if user and check_password_hash(user[3], password):
            session['user'] = email
            return redirect(url_for("main"))

        flash("Invalid email or password")
        return redirect(url_for("login"))

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.pop('user', None)
    flash("Logged out successfully")
    return redirect(url_for('login'))

@app.route('/main')
def main():
    if 'user' not in session:
        return redirect(url_for("login"))
    return render_template('index.html')

@app.route('/quote')
def quote():
    quote, author, category = get_quote()
    return render_template(
        'ai_quote.html',
        quote=quote,
        author=author,
        category=category
    )

if __name__ == '__main__':
    app.run(debug=True)
