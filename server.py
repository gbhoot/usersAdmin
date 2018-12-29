from flask import Flask, render_template, request, redirect, session, flash
from mysqlconnection import connectToMySQL
import re
from flask_bcrypt import Bcrypt
# create a regular expression object that we can use to run operations on
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')

app = Flask(__name__)
app.secret_key = "ssssssssssssshhh"
secrecy = Bcrypt(app)

def checkLoggedIn():
    if "userID" not in session:
        return False
    else:
        return True

def checkEmptyDB():
    mysql = connectToMySQL('admins')
    query = "SELECT id FROM users;"
    result = mysql.query_db(query)
    if result:
        return False
    else:
        return True

def checkEmailInDB(emailA):
    mysql = connectToMySQL('admins')
    query = "SELECT id, email FROM users WHERE email = %(email)s;"
    data = {
        'email' :   emailA
    }
    result = mysql.query_db(query, data)
    print(result)
    if result:
        return True
    else:
        return False

def checkUserAdmin(id):
    mysql = connectToMySQL('admins')
    query = "SELECT user_level FROM users WHERE id = %(userID)s;"
    data = {
        'userID'    :   id
    }
    result = mysql.query_db(query, data)
    print(result)
    if result:
        if result[0]['user_level'] > 1:
            return True
        else:
            return False

    return False

@app.route('/')
def index():
    if checkLoggedIn():
        if checkUserAdmin(session['userID']):
            return redirect('/admin')
        else:
            return redirect('/user')
    
    return render_template("index.html")

@app.route('/processNew', methods = ['POST'])
def processNew():
    # Check if not logged in
    # if not checkLoggedIn():
    #     print("should redirect to danger page")
    #     return redirect('/')

    # Check first name
    if len(request.form['first_name']) < 1:
        flash("Please enter first name", 'fName')
    elif len(request.form['first_name']) < 2:
        flash("First name should be at least 2 characters", 'fName')
    elif request.form['first_name'].isalpha() == False:
        flash("First name should only contain alphabetical characters", 'fName')

    # Check last name
    if len(request.form['last_name']) < 1:
        flash("Please enter last name", 'lName')
    elif len(request.form['last_name']) < 2:
        flash("Last name should be at least 2 characters", 'lName')
    elif request.form['last_name'].isalpha() == False:
        flash("Last name should only contain alphabetical characters", 'lName')

    # Check email
    if len(request.form['email']) < 1:
        flash("Please enter email address", 'email')
    elif not EMAIL_REGEX.match(request.form['email']):
        flash("Email address entered is invalid", 'email')
    elif checkEmailInDB(request.form['email']):
        flash("Email address entered is already registered, try logging in", 'email')

    # Check password
    if len(request.form['password']) < 1:
        flash("Please enter a password", 'password')
        flash("Please enter a password", 'pwconfirm')
    elif len(request.form['password']) < 9:
        flash("Please enter a valid password (too short)", 'password')

    # Check password
    elif len(request.form['pw_confirm']) < 1:
        flash("Please confirm your password", 'pwconfirm')
    elif request.form['password'] != request.form['pw_confirm']:
        flash("Passwords do not match", 'pwconfirm')
        flash("Passwords do not match", 'password')
    
    if '_flashes' in session.keys():
        return redirect('/')
    # else:
    pw_hash = secrecy.generate_password_hash(request.form['password'], 12)
    mysql = connectToMySQL('admins')
    if checkEmptyDB():
        user_level = 9
    else:
        user_level = 1
    query = ("INSERT INTO users (first_name, last_name, email, password, user_level) "+
    "VALUES (%(f_name)s, %(l_name)s, %(email)s, %(password)s, %(level)s);")
    data = {
        'f_name'    :   request.form['first_name'],
        'l_name'    :   request.form['last_name'],
        'email'     :   request.form['email'],
        'password'  :   pw_hash,
        'level'     :   user_level
    }
    result = mysql.query_db(query, data)
    session['userID'] = result
    print("registered user and logged user in: ", request.form['email'])
    if checkUserAdmin(session['userID']):
        return redirect('/admin')
    else:
        return redirect('/user')


@app.route('/processLogin', methods = ['POST'])
def processLogin():
    # Check if not logged in
    # if not checkLoggedIn():
    #     print("should redirect to danger page")
    #     return redirect('/')

    # Check email (entered else exists in database)
    if len(request.form['emailL']) < 1:
        flash("Please enter email address", 'emailL')
    # Check password(entered else matches for the email address entered)
    elif len(request.form['passwordL']) < 1:
        flash("Please enter password", "passwordL")

    if '_flashes' in session.keys():
        return redirect('/')
    
    mysql = connectToMySQL('admins')
    query = "SELECT id, email, password FROM users WHERE email = %(email)s;"
    data = {
        'email'    :   request.form['emailL']
    }
    result = mysql.query_db(query,data)

    if not result:
        flash("Email address entered was not found, please register", 'emailL')
    elif not secrecy.check_password_hash(result[0]['password'], request.form['passwordL']):
        flash("Password entered was incorrect", 'passwordL')
    
    if '_flashes' in session.keys():
        return redirect('/')
    else:
        session['userID'] = result[0]['id']
        if checkUserAdmin(session['userID']):
            return redirect('/admin')
        else :
            return redirect('/user')

@app.route('/admin')
def adminPage():
    # Check if not logged in
    if not checkLoggedIn():
        print("should redirect to danger page")
        return redirect('/')
    elif not checkUserAdmin(session['userID']):
        print("plain user attempted admin page")
        return redirect('/logout')

    mysql = connectToMySQL('admins')
    query = "SELECT id, CONCAT(first_name, ' ', last_name) as name, email, user_level FROM users;"
    users = mysql.query_db(query)
    
    query = "SELECT id, first_name FROM users WHERE id = %(userID)s;"
    data = {
        'userID'    :   session['userID']
    }
    user_info = mysql.query_db(query, data)
    
    return render_template("admin.html", users = users, user_info = user_info[0])

@app.route('/user')
def userPage():
    # Check if not logged in
    if not checkLoggedIn():
        print("should redirect to danger page")
        return redirect('/')
    elif checkUserAdmin(session['userID']):
        print("admin attempted user page")
        return redirect('/admin')
    
    mysql = connectToMySQL('admins')
    query = "SELECT id, first_name FROM users WHERE id = %(userID)s;"
    data = {
        'userID'    :   session['userID']
    }
    user_info = mysql.query_db(query, data)
    
    return render_template("user.html", user_info = user_info[0])

@app.route('/deleteUser', methods = ['POST'])
def delete():
    # Check if not logged in
    if not checkLoggedIn():
        print("should redirect to danger page")
        return redirect('/')
    elif not checkUserAdmin(session['userID']):
        print("user attempted admin page")
        return redirect('/logout')

    mysql = connectToMySQL('admins')
    query = "DELETE FROM users WHERE id = %(userID)s;"
    data = {
        'userID'    :   request.form['userID']
    }
    result = mysql.query_db(query, data)

    if session['userID'] == request.form['userID']:
        return redirect('/logout')
    else:
        return redirect('/admin')

@app.route('/newAdmin', methods = ['POST', 'GET'])
def newAdmin():
    # Check if not logged in
    if not checkLoggedIn():
        print("should redirect to danger page")
        return redirect('/')
    elif not checkUserAdmin(session['userID']):
        print("user attempted admin page")
        return redirect('/logout')
    elif not request.form:
        print("Form is:", request.form)
        return redirect('/admin')
    
    mysql = connectToMySQL('admins')
    query = "UPDATE users SET user_level = %(level)s WHERE id = %(userID)s;"
    data = {
        'level'     :   9,
        'userID'    :   request.form['userID']
    }
    result = mysql.query_db(query, data)
    print(result)

    return redirect('/admin')

@app.route('/loseAdmin', methods = ['POST', 'GET'])
def loseAdmin():
    # Check if not logged in
    if not checkLoggedIn():
        print("should redirect to danger page")
        return redirect('/')
    elif not checkUserAdmin(session['userID']):
        print("user attempted admin page")
        return redirect('/logout')
    elif not request.form:
        print("Form is:", request.form)
        return redirect('/admin')
    
    mysql = connectToMySQL('admins')
    query = "UPDATE users SET user_level = %(level)s WHERE id = %(userID)s;"
    data = {
        'level'     :   1,
        'userID'    :   request.form['userID']
    }
    result = mysql.query_db(query, data)
    print(result)

    return redirect('/admin')



@app.route('/logout')
def logout():
    # Check if not logged in
    if not checkLoggedIn():
        print("should redirect to danger page")
        return redirect('/')

    session.pop('userID')
    return redirect('/')

if __name__ == "__main__":
    app.run(debug=True)