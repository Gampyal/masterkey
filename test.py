# from flask import Flask, render_template
# import RPi.GPIO as GPIO
# import time
# import psycopg2

# app = Flask(__name__)

# # Configure GPIO pins
# GPIO.setmode(GPIO.BOARD)
# gate_control_pin = 11  # Change this to the actual GPIO pin connected to the relay
# GPIO.setup(gate_control_pin, GPIO.OUT)

# # Database configuration
# db_config = {
#     'host': 'your_postgresql_host',
#     'database': 'your_database_name',
#     'user': 'your_username',
#     'password': 'your_password'
# }

# # Open a connection to the database
# conn = psycopg2.connect(**db_config)
# cursor = conn.cursor()

# def open_gate():
#     print("Opening the gate")
#     GPIO.output(gate_control_pin, GPIO.HIGH)
#     time.sleep(2)  # Adjust the duration as needed
#     GPIO.output(gate_control_pin, GPIO.LOW)
#     log_event('Gate Opened')

# def close_gate():
#     print("Closing the gate")
#     GPIO.output(gate_control_pin, GPIO.HIGH)
#     time.sleep(2)  # Adjust the duration as needed
#     GPIO.output(gate_control_pin, GPIO.LOW)
#     log_event('Gate Closed')

# def log_event(event):
#     # Log the event to the PostgreSQL database
#     query = "INSERT INTO gate_log (event, timestamp) VALUES (%s, CURRENT_TIMESTAMP)"
#     cursor.execute(query, (event,))
#     conn.commit()

# # Routes and web application code...

# if __name__ == '__main__':
#     try:
#         app.run(host='0.0.0.0', port=5000, debug=True)
#     finally:
#         GPIO.cleanup()
#         cursor.close()
#         conn.close()






import time
from flask import session


session['opened_at'] = time.time()
print(session['opened_at'])