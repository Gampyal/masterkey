from flask import Flask, request, jsonify, session
import RPi.GPIO as GPIO
import time
import psycopg2

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Set a secret key for session management

# Configure GPIO pins
GPIO.setmode(GPIO.BOARD)
GPIO.setup(gate_control_pins, GPIO.OUT)

# Database configuration
db_config = {
    'host': 'your_postgresql_host',
    'database': 'your_database_name',
    'user': 'your_username',
    'password': 'your_password'
}

# Open a connection to the database
conn = psycopg2.connect(**db_config)
cursor = conn.cursor()

def authenticate(username, password):
    # Implement authentication logic here
    # Example: Check username and password against database
    return True  # Placeholder for authentication success

def authorize(username, gate_id):
    # Implement authorization logic here
    # Example: Check if the user has access to the specified gate
    return True  # Placeholder for authorization success

def open_gate(gate_id):
    print(f"Opening gate {gate_id}")
    GPIO.output(gate_control_pins[gate_id], GPIO.HIGH)
    session['gate_id'] = gate_id
    session['opened_at'] = time.time()  # Store the opening time in session
    log_event(gate_id, 'opened')

def close_gate(gate_id):
    print(f"Closing gate {gate_id}")
    GPIO.output(gate_control_pins[gate_id], GPIO.LOW)
    opened_at = session.pop('opened_at', None)  # Retrieve and remove opening time from session
    if opened_at:
        cursor.execute("UPDATE gate_logs SET closed_at = %s WHERE gate_id = %s AND opened_at = %s", (time.time(), gate_id, opened_at))
        conn.commit()
    session.pop('gate_id', None)  # Remove gate ID from session
    log_event(gate_id, 'closed')

def log_event(gate_id, event):
    # Log the event to the PostgreSQL database
    query = "INSERT INTO gate_logs (gate_id, event, timestamp) VALUES (%s, %s, CURRENT_TIMESTAMP)"
    cursor.execute(query, (gate_id, event))
    conn.commit()

@app.route('/open_gate', methods=['POST'])
def open_gate_route():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    gate_id = data.get('gate_id')
    
    if not authenticate(username, password):
        return jsonify({'error': 'Invalid username or password'}), 401

    if not authorize(username, gate_id):
        return jsonify({'error': 'Unauthorized to operate this gate'}), 403

    open_gate(gate_id)
    return jsonify({'message': f'Gate {gate_id} opened successfully'})

@app.route('/close_gate', methods=['POST'])
def close_gate_route():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    gate_id = data.get('gate_id')
    
    if not authenticate(username, password):
        return jsonify({'error': 'Invalid username or password'}), 401

    if not authorize(username, gate_id):
        return jsonify({'error': 'Unauthorized to operate this gate'}), 403

    close_gate(gate_id)
    return jsonify({'message': f'Gate {gate_id} closed successfully'})

if __name__ == '__main__':
    try:
        app.run(host='0.0.0.0', port=5000, debug=True)
    finally:
        GPIO.cleanup()
        cursor.close()
        conn.close()
