from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
import pymysql
import bcrypt
import logging
import os
from dotenv import load_dotenv
from datetime import datetime

load_dotenv()

app = Flask(__name__)
app.secret_key = "supersecretkey"

# Configure logging 
logging.basicConfig(level=logging.INFO)

# Database configuration
db_config = {
    'host': os.getenv('DB_HOST'),
    'user': os.getenv('DB_USER'),
    'password': os.getenv('DB_PASSWORD'),  # Change this to your actual DB password
    'database': os.getenv('DB_NAME')
}

# Function to get a database connection
def get_db_connection():
    try:
        connection = pymysql.connect(**db_config)
        logging.info("Connected to the database")
        return connection
    except pymysql.MySQLError as e:
        logging.error(f"Database connection failed: {e}")
        return None

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/services')
def services():
    return render_template('services.html')


@app.route('/user_login', methods=['GET', 'POST'])
def user_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['loginPassword'].encode('utf-8')

        connection = get_db_connection()
        if connection:
            cursor = connection.cursor()
            try:
                # Update the query to select the correct user identifier (id)
                cursor.execute("SELECT id, username, password FROM employees WHERE username = %s", (username,))
                result = cursor.fetchone()

                if result and bcrypt.checkpw(password, result[2].encode('utf-8')):  # result[2] is the hashed password
                    session['user_id'] = result[0]  # Store the 'id' (primary key) in the session
                    session['username'] = result[1]  # Optionally store the username as well
                    flash('Login successful!', 'success')
                    return redirect(url_for('user_dash'))  # Redirect to the user dashboard
                else:
                    flash('Invalid credentials. Please try again.', 'error')
            finally:
                cursor.close()
                connection.close()

    return render_template('user_login.html')


@app.route('/user_dash', methods=['GET', 'POST'])
def user_dash():
    if 'user_id' not in session:
        return redirect(url_for('user_login'))

    user_id = session['user_id']  # Now this will give you the correct numeric user_id
    print(f"user_id from session: {user_id}")

    if request.method == 'POST':
        action = request.form['action']
        connection = get_db_connection()

        try:
            with connection.cursor() as cursor:
                if action == 'check_in':
                    check_in_time = datetime.now()
                    cursor.execute(
                        "INSERT INTO user_attendance (user_id, check_in_time, attendance_date) VALUES (%s, %s, %s)",
                        (user_id, check_in_time, check_in_time.date())
                    )
                    connection.commit()
                    flash('Check-in successful!', 'success')

                elif action == 'check_out':
                    check_out_time = datetime.now()
                    cursor.execute(
                        "UPDATE user_attendance SET check_out_time = %s WHERE user_id = %s AND attendance_date = CURDATE() AND check_out_time IS NULL",
                        (check_out_time, user_id)
                    )
                    connection.commit()
                    flash('Check-out successful!', 'success')

        except pymysql.MySQLError as e:
            flash(f'Database error: {e}', 'error')

        finally:
            connection.close()

    return render_template('user_dash.html', username=session.get('username'))

# Route to render the HTML form
@app.route('/new_emp', methods=['GET', 'POST'])
def new_emp():
    if request.method == 'POST':
        # Get form data
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        email = request.form['email']
        dob = request.form['dob']
        username = request.form['username']
        password = request.form['password']

        # Hash the password for security
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # Insert the data into MySQL
        connection = get_db_connection()
        try:
            with connection.cursor() as cursor:
                sql = """
                INSERT INTO employees (first_name, last_name, email, dob, username, password)
                VALUES (%s, %s, %s, %s, %s, %s)
                """
                cursor.execute(sql, (first_name, last_name, email, dob, username, hashed_password))
                connection.commit()
                flash('Employee added successfully!', 'success')
        except pymysql.MySQLError as e:
            connection.rollback()  # Rollback transaction in case of error
            flash(f'Error adding employee: {e}', 'danger')
        finally:
            connection.close()  # Close the DB connection

        # Redirect to another page (e.g., '/services' or home page after submission)
        return redirect(url_for('index'))
    
    # For a GET request, render the employee form template
    return render_template('new_emp.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['loginEmail']
        password = request.form['loginPassword'].encode('utf-8')

        connection = get_db_connection()
        if connection:
            cursor = connection.cursor()
            try:
                cursor.execute("SELECT AdminID, password FROM hr_admin WHERE Email = %s", (email,))
                result = cursor.fetchone()

                if result and bcrypt.checkpw(password, result[1].encode('utf-8')):
                    session['user_id'] = result[0]
                    flash('Login successful!', 'success')
                    return redirect(url_for('services'))  # Redirect to services page
                else:
                    flash('Invalid credentials. Please try again.', 'error')
            finally:
                cursor.close()
                connection.close()

    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        full_name = request.form['name']
        email = request.form['email']
        password = request.form['password'].encode('utf-8')
        hashed_password = bcrypt.hashpw(password, bcrypt.gensalt())

        connection = get_db_connection()
        if connection:
            cursor = connection.cursor()
            try:
                cursor.execute("INSERT INTO hr_admin (Username, FullName, Email, password) VALUES (%s, %s, %s, %s)",
                               (username, full_name, email, hashed_password))
                connection.commit()
                flash('Account created successfully!', 'success')
                return redirect(url_for('login'))
            except pymysql.MySQLError as e:
                flash('Error creating account. Email may already exist.', 'error')
            finally:
                cursor.close()
                connection.close()

    return render_template('login.html')

@app.route('/employeedata')
def employeedata():
    conn = get_db_connection()
    if conn is None:
        flash('Database connection failed.', 'error')
        return redirect(url_for('index'))

    cursor = conn.cursor()
    
    try:
        cursor.execute("SELECT * FROM EmployeeDataManagement")  # Check table name case-sensitivity
        employees = cursor.fetchall()

        if not employees:
            flash('No employee data found.', 'warning')
    except pymysql.MySQLError as e:
        logging.error(f"Error fetching employee data: {e}")
        flash('Error fetching employee data.', 'error')
        employees = []  # Ensure employees is defined
    finally:
        cursor.close()
        conn.close()
    
    return render_template('employeedata.html', employees=employees)


@app.route('/perform')
def perform():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Fetch data from PerformanceTracking table
    cursor.execute("SELECT * FROM PerformanceTracking")
    performance_data = cursor.fetchall()
    
    cursor.close()
    conn.close()
    
    return render_template('perform.html', performance_data=performance_data)

@app.route('/leave')
def leave():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Fetch data from LeaveManagement table
    cursor.execute("SELECT * FROM LeaveManagement")
    leave_data = cursor.fetchall()
    
    cursor.close()
    conn.close()
    
    return render_template('leave.html', leave_data=leave_data)

@app.route('/payment')
def payment():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Fetch data from PayrollProcessing table
    cursor.execute("SELECT * FROM PayrollProcessing")
    payroll_data = cursor.fetchall()
    
    cursor.close()
    conn.close()
    
    return render_template('payment.html', payroll_data=payroll_data)

@app.route('/logout')
def logout():
    session.clear()  # Clear the session
    flash('You have been logged out.', 'success')
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
