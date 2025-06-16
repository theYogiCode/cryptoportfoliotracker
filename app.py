from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_mysqldb import MySQL
from db_config import db_config
from functools import wraps
import MySQLdb.cursors
import bcrypt

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# MySQL configuration
app.config.update(
    MYSQL_HOST=db_config['host'],
    MYSQL_USER=db_config['user'],
    MYSQL_PASSWORD=db_config['password'],
    MYSQL_DB=db_config['database']
)

mysql = MySQL(app)

# ROUTES

@app.route('/')
def home():
    return render_template('index.html')

#@app.route('/portfolio')
#def portfolio():
 #   return render_template('portfolio.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/glossary')
def glossary():
    return render_template('glossary.html')

@app.route('/faq')
def faq():
    return render_template('faq.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()

        if user and bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
            session['loggedin'] = True
            session['user_id'] = user['id']
            session['email'] = user['email']
            return jsonify({'message': 'Login successful'}), 200
        else:
            return jsonify({'error': 'Invalid credentials'}), 401

    return render_template('login.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        try:
            data = request.get_json()
            name = data.get('name')
            email = data.get('email')
            password = data.get('password')

            if not name or not email or not password:
                return jsonify({'error': 'All fields are required'}), 400

            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

            cursor = mysql.connection.cursor()
            cursor.execute("INSERT INTO users (name, email, password) VALUES (%s, %s, %s)",
                           (name, email, hashed_password.decode('utf-8')))
            mysql.connection.commit()
            cursor.close()
            return jsonify({'message': 'Signup successful'}), 200
        except Exception as e:
            print("Error during signup:", e)
            return jsonify({'error': 'Signup failed'}), 500

    return render_template('signup.html')


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'loggedin' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/portfolio')
@login_required
def portfolio():
    return render_template('portfolio.html')



@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)
