





from flask import Flask, request, jsonify
import psycopg2
import hashlib
import secrets
import bcrypt
import smtplib
from email.mime.text import MIMEText


app = Flask(__name__)

def connect_db():
    db = psycopg2.connect(
        host="localhost",
        user="postgres",
        password="newagepoSTgresql",
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
            
            else:
                cursor.execute("SELECT user_id, password FROM super_admin WHERE user_id=%s", (user_id,))
                admin_data = cursor.fetchone()
                if admin_data:
                    stored_hashed_password = admin_data[1]
                    user_unique_id = admin_data[0]

                    # Ensure stored_hashed_password is of type bytes
                    stored_hashed_password_bytes = stored_hashed_password.encode('utf-8')

                    if bcrypt.checkpw(password.encode('utf-8'), stored_hashed_password_bytes) and user_unique_id:
                        return jsonify({'success': True, 'message': f'Welcome, {admin_data[0]}'})
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
        with connect_db() as db:
            cursor = db.cursor()

            # Check for existing email
            cursor.execute("SELECT email FROM house_owners WHERE email = %s", (email,))
            existing_email = cursor.fetchone()

            if existing_email:
                raise ValueError("Email already exists")
            

            else:

                cursor.execute("INSERT INTO house_owners (email, first_name, last_name, phone_number) VALUES (%s, %s, %s, %s)", (email, first_name, last_name, phone_number))
                db.commit()
                

                combined_string = f"{email}{first_name}{last_name}{phone_number}"
                hashed_id = hashlib.md5(combined_string.encode()).hexdigest()
                new_owner_id = hashed_id[:11]

                new_owner_password = secrets.token_urlsafe(12)
                salt = bcrypt.gensalt()
                password = bcrypt.hashpw(new_owner_password.encode('utf8'), salt).decode('utf8')


                
                

                cursor.execute("INSERT INTO owners_credentials (email, unique_id, password, salt) VALUES (%s, %s, %s, %s)", (email, new_owner_id, password, salt))
                db.commit()

                cursor.execute("INSERT INTO gates (user_unique_id) VALUES (%s)", (new_owner_id,))
                db.commit()
        cursor.close()
        db.close()

        return new_owner_id, new_owner_password

    except Exception as e:
        print(f"Error generating credentials: {e}")
        return None, None
    



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

        # Log in to your email account
        server.login(sender_email, sender_password)

        # Send the email
        server.sendmail(sender_email, recipient_email, msg.as_string())

        # Disconnect from the server
        server.quit()

        return jsonify({'message': 'Email sent successfully!'})

    except smtplib.SMTPConnectError as e:
        return jsonify({'error': f'Failed to connect to the SMTP server. {e}'})

    except smtplib.SMTPAuthenticationError as e:
        return jsonify({'error': f'SMTP authentication failed. {e}'})

    except smtplib.SMTPException as e:
        return jsonify({'error': f'{e}'})

    except Exception as e:
        return jsonify({'error': f'An unexpected error occurred. {e}'})



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
    













if __name__ == '__main__':
    app.run(debug=True)
