from flask import Flask, render_template, request, redirect, session, flash
import re
from flask_mysqldb import MySQL
import MySQLdb.cursors
from werkzeug.utils import secure_filename
import os
import hashlib
from passlib.hash import sha256_crypt


app = Flask(__name__)
app.secret_key = 'your_secret_key'

UPLOAD_FOLDER = 'static/images'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def validate_email(email):
    pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    return re.match(pattern, email) is not None


def validate_password(password):
    pattern = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$"
    return re.match(pattern, password) is not None


# Configure MySQL
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'root'
app.config['MYSQL_DB'] = 'facebook'

mysql = MySQL(app)


#
# def create_stored_procedures():
#     procedures = [
#         """
#         CREATE PROCEDURE GetFriendsPosts(IN user_id INT)
#         BEGIN
#             SELECT posts.* FROM facebook.posts
#             JOIN facebook.friends ON posts.user_id = friends.friend_id
#             WHERE friends.user_id = user_id;
#         END;
#         """
#     ]
#
#     cursor = mysql.connection.cursor()
#     for procedure in procedures:
#         cursor.execute(procedure)
#     cursor.close()
#
# create_stored_procedures()

# fetch_posts = """
# #         CREATE PROCEDURE GetFriendsPosts(IN user_id INT)
# #         BEGIN
# #             SELECT posts.* FROM facebook.posts
# #             JOIN facebook.friends ON posts.user_id = friends.friend_id
# #             WHERE friends.user_id = user_id;
# #         END;
# #         """

# Function to create tables
def create_tables():
    with app.app_context():
        cursor = mysql.connection.cursor()
        cursor.execute('''
               CREATE TABLE IF NOT EXISTS users (
                   id INT AUTO_INCREMENT PRIMARY KEY,
                   username VARCHAR(50) NOT NULL UNIQUE,
                   email VARCHAR(50) NOT NULL,
                   password VARCHAR(100) NOT NULL,
                   profile_image VARCHAR(255) 
               )
           ''')
        cursor.execute('''
               CREATE TABLE IF NOT EXISTS posts (
                   id INT AUTO_INCREMENT PRIMARY KEY,
                   user_id INT NOT NULL,
                   title VARCHAR(100),
                   content TEXT,
                   FOREIGN KEY (user_id) REFERENCES users(id)
               )
           ''')
        cursor.execute('''
                    CREATE TABLE IF NOT EXISTS friend_requests (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        sender_id INT NOT NULL,
                        receiver_id INT NOT NULL,
                        status ENUM('pending', 'accepted', 'rejected') NOT NULL DEFAULT 'pending',
                        FOREIGN KEY (sender_id) REFERENCES users(id),
                        FOREIGN KEY (receiver_id) REFERENCES users(id)
                    )
                ''')
        cursor.execute('''
                    CREATE TABLE IF NOT EXISTS friends (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        user_id INT NOT NULL,
                        friend_id INT NOT NULL,
                        FOREIGN KEY (user_id) REFERENCES users(id),
                        FOREIGN KEY (friend_id) REFERENCES users(id)
                    )
                  ''')
        # cursor.execute(fetch_posts)
        mysql.connection.commit()
        cursor.close()


# Call the function to create tables
create_tables()


@app.route('/')
def index():
    return render_template('index.html')



# password = sha256_crypt.encrypt("password")
# password2 = sha256_crypt.encrypt("password")
#
# print(password)
# print(password2)
#
# print(sha256_crypt.verify("password", password))


# Function to hash the password
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

@app.route('/register', methods=['GET', 'POST'])
def register():
    msg=''
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        hashed_password = hash_password(password)
        profilepic = request.files['profilepic']

        if not validate_email(email):
            return 'Invalid email address'
        elif not validate_password(password):
            return 'Invalid password'

        if profilepic.filename == '':
            return 'No selected file'

        if profilepic and allowed_file(profilepic.filename): #allowed_file function checks if the file extension is allowed.
            filename = secure_filename(profilepic.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            profilepic.save(filepath)
        else:
            return 'Invalid file type'

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM users WHERE username = %s AND email = % s', (username,email))
        account = cursor.fetchone()
        if account:
            return 'Account already exists !'
        # elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
        #     msg = 'Invalid email address !'
        elif not re.match(r'[A-Za-z0-9]+', username):
            return  'Username must contain only characters and numbers !'
        elif not username or not password or not email:
            return 'Please fill out the form !'
        else:
        # cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)  # DictCursor is a cursor class that fetches rows from the database as dictionaries rather tan tuples.
            cursor.execute('INSERT INTO users (username, email, password, profile_image) VALUES (%s,%s, %s, %s)',
                           (username, email, hashed_password, filepath))
            mysql.connection.commit()
            cursor.close()


        return redirect('/login')
    return render_template('register.html', msg=msg)

@app.route('/forgotPassword', methods=['GET', 'POST'])
def forgotPassword():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        hashed_password = hash_password(password)

        if not validate_password(password):
            return 'Invalid password'

        cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cur.execute(f'SELECT * FROM users WHERE email = "{email}"')
        account = cur.fetchone()
        print(account)
        if account:
            cur.execute('UPDATE facebook.users SET password = %s WHERE email = %s',
                           (password, email))
            mysql.connection.commit()
            cur.close()
            return redirect('/login')
        else:
            return 'User not found'

    return render_template('forgotPassword.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        hashed_password = hash_password(password)

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM users WHERE  username = %s AND email = %s ',
                       (username, email))
        account = cursor.fetchone()

        if account:
            session['loggedin'] = True
            session['id'] = account['id']
            session['email'] = account['email']
            session['username'] = account['username']
            flash("You are successfully login")
            return redirect('/dashboard')
        else:
            flash("Invalid User")
            return 'Incorrect username/password!'

    return render_template('login.html')


@app.route('/edit_profile_pic', methods=['POST'])
def edit_profile_pic():
    if 'log gedin' in session:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        if request.method == 'POST':
            # Check if the post request has the file part
            if 'file' not in request.files:
                # flash('No file part')
                return redirect(request.url)
            file = request.files['file']
            # If the user does not select a file, the browser submits an empty part without filename
            if file.filename == '':
                # flash('No selected file')
                return redirect(request.url)
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
                # Update profile image path in the database
                cursor.execute('UPDATE users SET profile_image = %s WHERE id = %s', (file_path, session['id']))
                mysql.connection.commit()
                return 'Profile picture updated successfully!'
        return 'Invalid request'
    return redirect('/login')


@app.route('/dashboard')
def dashboard():
    if 'loggedin' in session:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

        # Get user's Posts
        cursor.execute('SELECT * FROM posts WHERE user_id = %s', [session['id']])
        user_posts = cursor.fetchall()

        #Get user's Friends
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('''
                SELECT users.username FROM friends
                JOIN users ON friends.friend_id = users.id
                WHERE friends.user_id = %s
                ''', [session['id']])
        friends = cursor.fetchall()

        # Get user's Friends suggestion
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('''
                  SELECT users.username FROM users
                  WHERE users.id NOT IN (
                      SELECT friend_id FROM friends WHERE user_id = %s
                  ) AND users.id != %s
              ''', (session['id'], session['id']))
        friendsSuggesion = cursor.fetchall()

        # Get friends' posts
        # cursor.callproc('GetFriendsPosts',[session['id']])
        cursor.execute('''
            SELECT posts.* FROM posts
            JOIN friends ON posts.user_id = friends.friend_id
            WHERE friends.user_id = %s
        ''', [session['id']])
        friend_posts = cursor.fetchall()

        # Get user's profile picture path
        cursor.execute('SELECT profile_image FROM users WHERE id = %s', [session['id']])
        profile_image = cursor.fetchone()['profile_image'] if cursor.rowcount > 0 else None

        return render_template('dashboard.html', username=session['username'], user_posts=user_posts,
                               friend_posts=friend_posts,profile_image=profile_image,friends=friends,friendsSuggesion=friendsSuggesion)
    return redirect('/login')


@app.route('/addpost', methods=['GET', 'POST'])
def addpost():
    if 'loggedin' in session:
        if request.method == 'POST':
            title = request.form['title']
            content = request.form['content']

            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute('INSERT INTO posts (user_id, title, content) VALUES (%s, %s, %s)',
                           (session['id'], title, content))
            mysql.connection.commit()
            cursor.close()

            return redirect('/dashboard')
        return render_template('addpost.html')
    return redirect('/login')


@app.route('/send_friend_request', methods=['POST'])
def send_friend_request():
    if 'loggedin' in session:
        receiver_username = request.form['username']

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT id FROM users WHERE username = %s', [receiver_username])
        receiver = cursor.fetchone()

        if receiver:
            cursor.execute('INSERT INTO friend_requests (sender_id, receiver_id) VALUES (%s, %s)',
                           (session['id'], receiver['id']))
            mysql.connection.commit()

        cursor.close()

        return redirect('/dashboard')
    return redirect('/login')


@app.route('/view_friend_requests')
def view_friend_requests():
    if 'loggedin' in session:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('''
            SELECT friend_requests.id, users.username FROM friend_requests
            JOIN users ON friend_requests.sender_id = users.id
            WHERE friend_requests.receiver_id = %s AND friend_requests.status = 'pending'
        ''', [session['id']])
        requests = cursor.fetchall()
        return render_template('friend_requests.html', requests=requests)
    return redirect('/login')


@app.route('/accept_friend_request/<int:request_id>')
def accept_friend_request(request_id):
    if 'loggedin' in session:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('UPDATE friend_requests SET status = %s WHERE id = %s', ('accepted', request_id))
        cursor.execute('''
            INSERT INTO friends (user_id, friend_id)
            SELECT receiver_id, sender_id FROM friend_requests WHERE id = %s
        ''', [request_id])
        cursor.execute('''
            INSERT INTO friends (user_id, friend_id)
            SELECT sender_id, receiver_id FROM friend_requests WHERE id = %s
        ''', [request_id])
        mysql.connection.commit()
        cursor.close()
        return redirect('/view_friend_requests')
    return redirect('/login')

@app.route('/reject_friend_request/<int:request_id>')
def reject_friend_request(request_id):
    if 'loggedin' in session:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('UPDATE friend_requests SET status = %s WHERE id = %s', ('rejected', request_id))
        mysql.connection.commit()
        cursor.close()
        return redirect('/view_friend_requests')
    return redirect('/login')

# @app.route('/get_friends')
# def get_friends(user_id):
#
#     cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
#     cursor.execute('''
#         SELECT users.username FROM friends
#         JOIN users ON friends.friend_id = users.id
#         WHERE friends.user_id = %s
#     ''', [user_id])
#     friends = cursor.fetchall()
#     cursor.close()
#     return friends
#
# @app.route('/see_friends')
# def see_friends():
#     if 'loggedin' in session:
#         friends = get_friends(session['id'])
#         return render_template('dashboard.html', friends=friends)
#     return redirect('/login')

@app.route('/logout')
def logout():
    session.pop('loggedin', None)
    session.pop('id', None)
    session.pop('username', None)
    return redirect('/login')


if __name__ == '__main__':
    app.run(debug=False)
