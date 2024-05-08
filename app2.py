





from datetime import datetime
import logging
from flask import Flask, request, jsonify, session
import psycopg2
import hashlib
import secrets
import bcrypt
import smtplib
# import RPi.GPIO as GPIO
import time
from email.mime.text import MIMEText


app = Flask(__name__)

def connect_db():
    db = psycopg2.connect(
        host="localhost",
        user="postgres",
        password="postgrsQl",
        database="masterkeydb"
    )
    return db




@app.route('/new_super_admin', methods=['POST'])
def new_super_admin():
    try:
        data = request.get_json()
        db = connect_db()
        cursor = db.cursor()

        email = data['email']
        first_name = data['first_name']
        last_name = data['last_name']
        user_id = data['user_id']
        salt = bcrypt.gensalt()

        # Hash the password with the generated salt
        password = bcrypt.hashpw(data['password'].encode('utf8'), salt).decode('utf8')

        phone_number = data['phone_number']

        cursor.execute("INSERT INTO super_admin (email, first_name, last_name, user_id, password, salt, phone_number) VALUES (%s, %s, %s, %s, %s, %s, %s)", (email, first_name, last_name, user_id, password, salt, phone_number))
        db.commit()

        cursor.close()
        db.close()

        return jsonify({'message': 'Super admin created successfully!'})

    except Exception as e:
        return jsonify({'error': f'Error creating super admin: {e}'})
    






@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        user_id = data.get('user_id')
        password = data.get('password')

        if not user_id or not password:
            raise ValueError("Missing user_id or password in the request")

        with connect_db() as db, db.cursor() as cursor:
            cursor.execute("SELECT unique_id, password FROM owners_credentials WHERE unique_id=%s", (user_id,))
            user_data = cursor.fetchone()
            

            if user_data:
                stored_hashed_password = user_data[1]
                user_unique_id = user_data[0]

                # Ensure stored_hashed_password is of type bytes
                stored_hashed_password_bytes = stored_hashed_password.encode('utf-8')

                if bcrypt.checkpw(password.encode('utf-8'), stored_hashed_password_bytes) and user_unique_id:
                    return jsonify({'success': True, 'message': f'Welcome, {user_data[0]}'})
                else:
                    return jsonify({'success': False, 'message': 'Invalid login credentials'})
                
            cursor.close()
            db.close()
                
    except Exception as e:
        return jsonify({'error': f'An unexpected error occurred: {str(e)}'})
    


@app.route('/new_house_owner_credentials_to_mail', methods=['POST'])
def new_house_owner():
    try:
        data = request.get_json()
        email = data['email']
        first_name = data['first_name']
        last_name = data['last_name']
        phone_number = data['phone_number']

        new_owner_id, password = generate_owner_credentials(email, first_name, last_name, phone_number)

        print(new_owner_id, password)
        send_email(new_owner_id, password, email, first_name)

        return jsonify({
        'message': "You're doing great! Check your email for your login credentials.",
        'new_owner_id': new_owner_id,
        'new_owner_password': password
    })

    except Exception as e:
        return jsonify({'error': f'Error: {e}'})
    

def generate_owner_credentials(email, first_name, last_name, phone_number):
    try:
        db = connect_db()
        cursor = db.cursor()

        cursor.execute("INSERT INTO house_owners (email, first_name, last_name, phone_number) VALUES (%s, %s, %s, %s)", (email, first_name, last_name, phone_number))
        db.commit()

        combined_string = f"{email}{first_name}{last_name}{phone_number}"

        hashed_id = hashlib.md5(combined_string.encode()).hexdigest()

        new_owner_id = hashed_id[:11]

        new_owner_password = secrets.token_urlsafe(12)
        print(new_owner_id, new_owner_password)
        salt = bcrypt.gensalt()

        # Hash the password with the generated salt
        password = bcrypt.hashpw(new_owner_password.encode('utf8'), salt).decode('utf8')

        
        cursor.execute("INSERT INTO owners_credentials (email, unique_id, password, salt) VALUES (%s, %s, %s, %s)", (email, new_owner_id, password, salt))
        db.commit()

        cursor.execute("INSERT INTO gates (user_unique_id) VALUES (%s)", (new_owner_id))
        db.commit()

        cursor.close()
        db.close()

        return new_owner_id, new_owner_password

    except Exception as e:
        return None, None 
    



# def send_email(user_id, password, recipient_email, first_name):
#     # Email configuration
#     sender_email = "samuelgampyal@gmail.com"  # replace with your email address
#     sender_password = "wgzq tlvd qwvw vfki"  # replace with your email password
#     subject = "Your New Account Information"

#     # Message body
#     message_body = f"Hello {first_name},\n\nWelcome to Masterkey.\nYour new account has been created.\n\nUser ID: {user_id}\nPassword: {password}\nLogin to change your password immediately.\n\nThank you for choosing Masterkey.\nBest regards."

#     # Create the MIMEText object
#     msg = MIMEText(message_body)
#     msg["Subject"] = subject
#     msg["From"] = sender_email
#     msg["To"] = recipient_email

#     try:
#         # Connect to the SMTP server
#         server = smtplib.SMTP("smtp.gmail.com", 587)
#         server.starttls()

#         # Log in to your email account
#         server.login(sender_email, sender_password)

#         # Send the email
#         server.sendmail(sender_email, recipient_email, msg.as_string())

#         # Disconnect from the server
#         server.quit()

#         print(f'Successfully sent email to {recipient_email}')

#         return jsonify({'message': 'Email sent successfully!'})

#     except smtplib.SMTPConnectError as e:
#         return jsonify({'error': f'Failed to connect to the SMTP server. {e}'})

#     except smtplib.SMTPAuthenticationError as e:
#         return jsonify({'error': f'SMTP authentication failed. {e}'})

#     except smtplib.SMTPException as e:
#         return jsonify({'error': f'{e}'})

#     except Exception as e:
#         return jsonify({'error': f'An unexpected error occurred. {e}'})


def send_email(user_id, password, recipient_email, first_name):
    # Email configuration
    sender_email = "samuelgampyal@gmail.com"  # replace with your email address
    sender_password = "wgzq tlvd qwvw vfki"  # replace with your email password
    subject = "Your New Account Information"

    # Message body
    message_body = f"Hello {first_name},\n\nWelcome to Masterkey.\nYour new account has been created.\n\nUser ID: {user_id}\nPassword: {password}\nLogin to change your password immediately.\n\nThank you for choosing Masterkey.\nBest regards."

    # Create the MIMEText object
    msg = MIMEText(message_body)
    msg["Subject"] = subject
    msg["From"] = sender_email
    msg["To"] = recipient_email

    try:
        # Connect to the SMTP server
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.set_timeout(10)  # Set a timeout for the connection (in seconds)

        # Log in to your email account
        server.login(sender_email, sender_password)

        # Send the email
        server.sendmail(sender_email, recipient_email, msg.as_string())

        # Disconnect from the server
        server.quit()

        logging.info(f'Successfully sent email to {recipient_email}')
        return {'message': 'Email sent successfully!'}

    except smtplib.SMTPConnectError as e:
        logging.error(f'Failed to connect to the SMTP server: {e}')
        return {'error': 'Failed to connect to the SMTP server'}, 500

    except smtplib.SMTPAuthenticationError as e:
        logging.error(f'SMTP authentication failed: {e}')
        return {'error': 'SMTP authentication failed'}, 500

    except smtplib.SMTPException as e:
        logging.error(f'SMTP error: {e}')
        return {'error': 'SMTP error'}, 500

    except Exception as e:
        logging.error(f'An unexpected error occurred: {e}')
        return {'error': 'An unexpected error occurred'}, 500



def validate_password(password):
    if len(password) < 8:
        print("Error: Password should be at least 8 characters long.")
        return False
    elif not any(char.isdigit() for char in password):
        print("Error: Password should contain at least one digit.")
        return False
    elif not any(char.islower() for char in password):
        print("Error: Password should contain at least one lowercase letter.")
        return False
    elif not any(char.isupper() for char in password):
        print("Error: Password should contain at least one uppercase letter.")
        return False
    elif not any(char in "!@#$%^&*()-_=+[]{}\|;:'\"<>,.?/" for char in password):
        print("Error: Password should contain at least one special character.")
        return False
    else:
        return True




@app.route('/password_reset', methods=['POST'])
def initial_password_reset():
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')

        if not email or not password:
            return jsonify({'error': 'Email and password are required'}), 400

        if not validate_password(password):
            return jsonify({'error': 'Invalid password format'}), 400

        with connect_db() as db, db.cursor() as cursor:
            cursor.execute("SELECT * FROM owners_credentials WHERE email = %s", (email,))
            user_data = cursor.fetchone()
            user_id = user_data[2]

            if not user_data:
                return jsonify({'error': 'User not found'}), 404

            # Generate a new salt for the password
            new_salt = bcrypt.gensalt()

            # Hash the new password with the new salt
            hashed_password = bcrypt.hashpw(password.encode(), new_salt).decode()

            # Update the password and salt in the database
            cursor.execute("UPDATE owners_credentials SET password = %s, salt = %s WHERE email = %s", (hashed_password, new_salt, email))
            db.commit()

            return jsonify({'message': f"Password updated successfully for user {user_id}"}), 200

    except psycopg2.Error as e:
        return jsonify({'error': f'Database error: {e}'}), 500

    except Exception as e:
        return jsonify({'error': f'An unexpected error occurred: {e}'}), 500
    







# def assign_gate(user_unique_id, gate_unique_id):
#     try:
#         with connect_db() as db, db.cursor() as cursor:
#             # Check that user exist
#             cursor.execute("SELECT user_unique_id FROM gates WHERE user_unique_id = %s", (user_unique_id,))
#             user_exists = bool(cursor.rowcount)
#             # Assign the gate to the user
#             if user_exists:
#                 cursor.execute("UPDATE gates SET gate_unique_id = %s WHERE user_unique_id = %s",  (gate_unique_id, user_unique_id,))

#                 return True
#     except Exception as e:
#         print("Unexpected error:", type(e), e)
#         return False
    



            
            

# @app.route('/gate/assign', methods=['POST'])
# def assign_gpio():
#     try:
#         data = request.get_json()
#         user_unique_id = data.get('user_unique_id')
#         gate_unique_id = data.get('gate_unique_id')
        

#         gate_assign = assign_gate(user_unique_id, gate_unique_id)
#         if gate_assign:
#             return jsonify({'Success': f"{gate_unique_id} successfully assigned to {user_unique_id}"}), 200
#     except Exception as e:
#         return jsonify({'error': f"{e}"}), 500






# # Configure GPIO pins
# GPIO.setmode(GPIO.BOARD)
# # Define the GPIO pins for gates (e.g., gate_control_pins = {1: 11, 2: 12, ...})
# def assign_gpio_pin(gate_unique_id, gpio_pin):
#     try:
#         with connect_db() as db, db.cursor() as cursor:
#             gate_control_pins = {gate_unique_id: gpio_pin}
#             for gpio_pin in gate_control_pins.values():
#                 GPIO.setup(gpio_pin, GPIO.OUT)
#                 cursor.execute("UPDATE gates SET gpio_pin = %s WHERE gate_unique_id = %s",  (gpio_pin, gate_unique_id))
#             db.commit()
#         return True
#     except Exception as e:
#         print("Error:", e)
#         return False
    

# @app.route('/gate/config', methods=['POST'])
# def assign_gpio():
#     try:
#         data = request.get_json()
#         gate_unique_id = data.get('gate_unique_id')
#         gpio_pin = data.get('gpio_pin')

#         gpio_assign = assign_gpio_pin(gate_unique_id, gpio_pin)
#         if gpio_assign:
#             return jsonify({'Success': f"{gpio_pin} successfully assigned to {gate_unique_id}"}), 200
#     except Exception as e:
#         return jsonify({'error': f"{e}"}), 500
    






# def unassign_gpio_pin(gate_unique_id, gpio_pin):
#     try:
#         with connect_db() as db, db.cursor() as cursor:
#             cursor.execute("UPDATE gates SET gpio_pin = NULL WHERE gate_unique_id = %s AND gpio_pin = %s",  (gate_unique_id, gpio_pin))
#             db.commit()
#         return True
#     except Exception as e:
#         print("Error:", e)
#         return False

# @app.route('/gate/deconfig', methods=['POST'])
# def unassign_gpio():
#     try:
#         data = request.get_json()
#         gate_unique_id = data.get('gate_unique_id')
#         gpio_pin = data.get('gpio_pin')

#         gpio_unassign = unassign_gpio_pin(gate_unique_id, gpio_pin)
#         if gpio_unassign:
#             return jsonify({'Success': f"{gpio_pin} successfully unassigned from {gate_unique_id}"}), 200
#         else:
#             return jsonify({'error': 'Failed to unassign GPIO pin'}), 500
#     except Exception as e:
#         return jsonify({'error': f"{e}"}), 500



    





# def authenticate(user_unique_id, password):
#     try:
#         db = connect_db
#         cursor = db.cursor()
#         cursor.execute("SELECT unique_id, password FROM owners_credentials WHERE unique_id=%s", (user_unique_id,))
#         user_data = cursor.fetchone()
#         if user_data:
#             stored_hashed_password = user_data[1].encode('utf-8')
#             if bcrypt.checkpw(password.encode('utf-8'), stored_hashed_password):
#                 return True
#     except psycopg2.Error as e:
#         print("Database error:", e)
#     finally:
#         cursor.close()
#         db.close()
#     return False


# def authorize(user_unique_id, gate_gpio_pin):
#     try:
#         db = connect_db()
#         cursor = db.cursor()
#         cursor.execute("SELECT user_unique_id, gpio_pin FROM gates WHERE user_unique_id=%s", (user_unique_id,))
#         user_data = cursor.fetchone()
#         if user_data:
#             gpio_pin = user_data[1]
#             unique_user_id = user_data[0]
#             if gpio_pin == gate_gpio_pin and unique_user_id == user_unique_id:
#                 return True
#     except psycopg2.Error as e:
#         print("Database error:", e)
#     finally:
#         cursor.close()
#         db.close()
#     return False



# def open_gate(gate_id):
#     try:
#         db = connect_db()
#         cursor = db.cursor()
#         print(f"Opening gate {gate_id}")
#         cursor.execute("SELECT gate_unique_id, gpio_pin from gates WHERE gate_unique_id=%s", (gate_id,))
#         gate_control_pins = dict(cursor.fetchall())
#         GPIO.output(gate_control_pins[1], GPIO.HIGH)
#         session['gate_id'] = gate_control_pins[0]
#         session['opened_at'] = time.time()  # Store the opening time in session
#         opened_at_datetime = datetime.fromtimestamp(session['opened_at'])
#         formatted_datetime = opened_at_datetime.strftime("%Y-%m-%d %H:%M:%S")
#         check_gpio = cursor.execute("SELECT gpio_pin FROM gates WHERE gpio_pin = %s", (gate_id))
#         if check_gpio:
#             cursor.execute("INSERT INTO gate_logs (gate_unique_id, opened_at) VALUES (%s, %s)", (gate_id, formatted_datetime))
#             db.commit()
#     except (psycopg2.Error, KeyError) as e:
#         print("Error opening gate:", e)
#     finally:
#         cursor.close()
#         db.close()


# def close_gate(gate_id):
#     try:
#         db = connect_db()
#         cursor = db.cursor()
#         print(f"Closing gate {gate_id}")
#         cursor.execute("SELECT gate_unique_id, gpio_pin from gates WHERE gate_unique_id=%s", (gate_id,))
#         gate_control_pins = dict(cursor.fetchall())
#         GPIO.output(gate_control_pins[1], GPIO.LOW)
#         opened_at = session.pop('opened_at', None)  # Retrieve and remove opening time from session
#         if opened_at:
#             opened_at_datetime = datetime.fromtimestamp(session['opened_at'])
#             formatted_opened_at_datetime = opened_at_datetime.strftime("%Y-%m-%d %H:%M:%S")
#             closed_at = time.time()
#             formatted_closed_at_datetime = closed_at.strftime("%Y-%m-%d %H:%M:%S")
#             cursor.execute("UPDATE gate_logs SET closed_at = %s WHERE gate_unique_id = %s AND opened_at = %s", (formatted_closed_at_datetime, gate_id, formatted_opened_at_datetime))
#             db.commit()
#         session.pop('gate_id', None)  # Remove gate ID from session
#     except (psycopg2.Error, KeyError) as e:
#         print("Error closing gate:", e)
#     finally:
#         cursor.close()
#         db.close()


# @app.route('/open_gate', methods=['POST'])
# def open_gate_route():
#     data = request.get_json()
#     user_unique_id = data.get('username')
#     password = data.get('password')
#     gate_id = data.get('gate_id')
    
#     if authenticate(user_unique_id, password):
#         if authorize(user_unique_id, gate_id):
#             open_gate(gate_id)
#             return jsonify({'status': f'Gate {gate_id} opened'})
#         else:
#             return jsonify({'error': 'Unauthorized access'}), 403
#     else:
#         return jsonify({'error': 'Invalid username or password'}), 401
    

# @app.route('/close_gate', methods=['POST'])
# def close_gate_route():
#     data = request.get_json()
#     username = data.get('username')
#     password = data.get('password')
#     gate_id = data.get('gate_id')
    
#     if authenticate(username, password):
#         if authorize(username, gate_id):
#             close_gate(gate_id)
#             return jsonify({'status': f'Gate {gate_id} closed'})
#         else:
#             return jsonify({'error': 'Unauthorized access'}), 403
#     else:
#         return jsonify({'error': 'Invalid username or password'}), 401
    














if __name__ == '__main__':
    app.run(debug=True)
    # try:
    #     app.run(debug=True)
    # finally:
    #     GPIO.cleanup()