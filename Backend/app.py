import pymysql
import uuid
from flask import Flask, jsonify, request, session
from flask_cors import CORS
from datetime import datetime
import bcrypt
import logging

# Initialize Flask app
app = Flask(__name__)

# Configure session
app.secret_key = 'a_secure_random_string_here'  # Replace this with a secure key
app.config['SESSION_TYPE'] = 'filesystem'  # Store session data on the server side
app.config['SESSION_PERMANENT'] = True  # Make the session persistent
app.config['SESSION_USE_SIGNER'] = True  # Sign the session cookies
app.config['SESSION_COOKIE_SAMESITE'] = 'None'  # Allow cross-site cookies
app.config['SESSION_COOKIE_SECURE'] = True  # Required for cross-site cookies

# Configure CORS
CORS(app, supports_credentials=True, origins=["http://localhost:3000"])

# Database connection
def connect_to_db():
    """Establish a connection to the MySQL database."""
    return pymysql.connect(
        host="34.70.201.72",
        user="flaskapp",
        password="Flaskapp",
        database="mental_health_tracker_final",
        charset='utf8mb4',
        cursorclass=pymysql.cursors.DictCursor
    )

# User Registration Route
@app.route('/register', methods=['POST'])
def register_user():
    """Handle user registration."""
    data = request.json
    username = data['username']
    email = data['email']
    password = data['password']
    age = data['age']
    gender = data['gender']
    country = data['country']
    occupation = data['occupation']

    # Hash the password for security
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    connection = connect_to_db()
    cursor = connection.cursor()

    try:
        cursor.execute("SELECT COALESCE(MAX(user_id), 0) + 1 AS next_id FROM User")
        next_user_id = cursor.fetchone()['next_id']

        cursor.execute(
            "INSERT INTO User (user_id, username, email, password, age, gender, country, occupation) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
            (next_user_id, username, email, hashed_password, age, gender, country, occupation)
        )
        connection.commit()
        logging.info(f"User registered successfully: {username}")
        return jsonify({'success': True, 'message': 'User registered successfully'}), 201

    except Exception as e:
        connection.rollback()
        logging.error("Error registering user: ", e)
        return jsonify({'success': False, 'message': 'Registration failed'}), 500

    finally:
        cursor.close()
        connection.close()


# User Login Route
@app.route('/login', methods=['POST'])
def login_user():
    """Handle user login."""
    data = request.json
    email = data['email']
    password = data['password']

    logging.info(f"Login attempt: {email}")

    connection = connect_to_db()
    cursor = connection.cursor()

    try:
        cursor.execute("SELECT * FROM User WHERE email = %s", (email,))
        user = cursor.fetchone()

        if user and bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
            session['user_id'] = user['user_id']  # Store user_id in session
            logging.info(f"Login successful for user_id: {user['user_id']}")
            return jsonify({'success': True, 'user_id': user['user_id'], 'username': user['username']}), 200
        else:
            logging.warning(f"Invalid login attempt for email: {email}")
            return jsonify({'success': False, 'message': 'Invalid credentials'}), 401

    except Exception as e:
        logging.error(f"Error logging in user: {e}")
        return jsonify({'success': False, 'message': 'Login failed'}), 500

    finally:
        cursor.close()
        connection.close()


# User Logout Route
@app.route('/logout', methods=['POST'])
def logout_user():
    """Handle user logout."""
    session.pop('user_id', None)  # Remove user_id from session
    logging.info("User logged out successfully.")
    return jsonify({'success': True, 'message': 'Logout successful'}), 200


# Check if user is logged in
def check_user_logged_in():
    """Check if the user is logged in by checking session."""
    return 'user_id' in session


# Daily Log Route
@app.route('/daily_log', methods=['GET', 'POST'])
def daily_log():
    """Handle daily log submission and retrieval."""
    if not check_user_logged_in():
        return jsonify({'success': False, 'message': 'User not logged in'}), 401

    connection = connect_to_db()
    cursor = connection.cursor()

    if request.method == 'POST':
        data = request.json
        try:
            cursor.execute("SELECT COALESCE(MAX(log_id), 0) + 1 AS next_id FROM DailyLog")
            next_log_id = cursor.fetchone()['next_id']

            cursor.callproc('ProcessDailyLog', (
            next_log_id, 
            session['user_id'], 
            datetime.now().strftime('%Y-%m-%d'), 
            data['screen_time'], 
            data['social_media_time'], 
            data['gaming_time'], 
            data['sleep_hours'], 
            data['physical_activity_hours']
        ))

            connection.commit()
            return jsonify({'success': True, 'message': 'Log added successfully'}), 201

        except Exception as e:
            connection.rollback()
            logging.error(f"Error inserting daily log: {e}")
            return jsonify({'success': False, 'message': 'Failed to insert log'}), 500

    elif request.method == 'GET':
        try:
            print(session['user_id'])
            cursor.execute("SELECT * FROM DailyLog WHERE user_id = %s", (session['user_id'],))
            logs = cursor.fetchall()
            print(logs)
            return jsonify({'logs': logs}), 200

        except Exception as e:
            logging.error(f"Error fetching daily logs: {e}")
            return jsonify({'success': False, 'message': 'Failed to fetch logs'}), 500

        finally:
            cursor.close()
            connection.close()

@app.route('/user_dashboard', methods=['GET'])
def user_dashboard():
    """Fetch rewards, recommendations, and logs for the user."""
    if 'user_id' not in session:
        return jsonify({'message': 'User not logged in'}), 401

    user_id = session['user_id']
    connection = connect_to_db()
    cursor = connection.cursor()

    try:
        # Fetch total rewards for the user
        cursor.execute("""
            SELECT SUM(points) AS total_rewards 
            FROM Reward 
            WHERE user_id = %s
        """, (user_id,))
        total_rewards = cursor.fetchone()['total_rewards'] or 0  # Default to 0 if no rewards

        # Fetch recommendations for the user
        cursor.execute("""
            SELECT recommendation_id, content, date 
            FROM Recommendation 
            WHERE user_id = %s
        """, (user_id,))
        recommendations = cursor.fetchall()

        # Fetch logs for the user
        cursor.execute("""
            SELECT log_id, screen_time, social_media_time, gaming_time, sleep_hours, physical_activity_hours, stress_level, mental_health_status 
            FROM DailyLog 
            WHERE user_id = %s
        """, (user_id,))
        logs = cursor.fetchall()

        # Returning the response as JSON
        return jsonify({
            'total_rewards': total_rewards,
            'recommendations': recommendations,
            'logs': logs
        }), 200

    except Exception as e:
        logging.error(f"Error fetching user dashboard data: {e}")
        return jsonify({'message': 'Failed to fetch data'}), 500

    finally:
        cursor.close()
        connection.close()

@app.route('/update_daily_log', methods=['POST'])
def update_daily_log():
    """Handle daily log update."""
    if not check_user_logged_in():
        return jsonify({'success': False, 'message': 'User not logged in'}), 401

    connection = connect_to_db()
    cursor = connection.cursor()

    data = request.json
    log_id = data['log_id']
    screen_time = data['screen_time']
    social_media_time = data['social_media_time']
    gaming_time = data['gaming_time']
    sleep_hours = data['sleep_hours']
    physical_activity_hours = data['physical_activity_hours']

    try:
        # Delete the old log data before inserting the new one
        cursor.execute("DELETE FROM DailyLog WHERE log_id = %s", (log_id,))
        
        # Get the next log_id
        cursor.execute("SELECT COALESCE(MAX(log_id), 0) + 1 AS next_id FROM DailyLog")
        next_log_id = cursor.fetchone()['next_id']

        # Call the stored procedure to process the log and calculate stress level & mental health status
        cursor.callproc('ProcessDailyLog', (
            next_log_id, 
            session['user_id'], 
            datetime.now().strftime('%Y-%m-%d'), 
            screen_time, 
            social_media_time, 
            gaming_time, 
            sleep_hours, 
            physical_activity_hours
        ))

        # Commit the transaction
        connection.commit()
        
        return jsonify({'success': True, 'message': 'Log updated successfully'}), 200

    except Exception as e:
        connection.rollback()
        logging.error(f"Error updating daily log: {e}")
        return jsonify({'success': False, 'message': 'Failed to update log'}), 500

    finally:
        cursor.close()
        connection.close()


@app.route('/delete_daily_log', methods=['POST'])
def delete_daily_log():
    """Delete a user's daily log."""
    if not check_user_logged_in():
        return jsonify({'success': False, 'message': 'User not logged in'}), 401

    log_id = request.json['log_id']

    connection = connect_to_db()
    cursor = connection.cursor()

    try:
        cursor.execute("DELETE FROM DailyLog WHERE log_id = %s AND user_id = %s", (log_id, session['user_id']))
        connection.commit()
        return jsonify({'success': True, 'message': 'Daily log deleted successfully'}), 200
    except Exception as e:
        connection.rollback()
        logging.error("Error deleting daily log:", e)
        return jsonify({'success': False, 'message': 'Failed to delete daily log'}), 500
    finally:
        cursor.close()
        connection.close()

@app.route('/user_dashboard/search', methods=['GET'])
def search_logs():
    """Handle log search by keyword."""
    if not check_user_logged_in():
        return jsonify({'success': False, 'message': 'User not logged in'}), 401

    keyword = request.args.get('keyword', '')
    user_id = session['user_id']

    connection = connect_to_db()
    cursor = connection.cursor()

    try:
        # Search for logs by keyword in relevant fields (e.g., screen time, social media time, etc.)
        query = """
            SELECT * FROM DailyLog
            WHERE user_id = %s AND (
                screen_time LIKE %s OR
                social_media_time LIKE %s OR
                gaming_time LIKE %s OR
                sleep_hours LIKE %s OR
                physical_activity_hours LIKE %s
            )
        """
        search_pattern = f"%{keyword}%"
        cursor.execute(query, (user_id, search_pattern, search_pattern, search_pattern, search_pattern, search_pattern))
        logs = cursor.fetchall()

        return jsonify({'logs': logs}), 200

    except Exception as e:
        logging.error(f"Error searching logs: {e}")
        return jsonify({'success': False, 'message': 'Failed to search logs'}), 500
    finally:
        cursor.close()
        connection.close()

@app.route('/delete_user', methods=['POST'])
def delete_user():
    """Delete the user's account and all associated data."""
    if not check_user_logged_in():
        return jsonify({'success': False, 'message': 'User not logged in'}), 401

    connection = connect_to_db()
    cursor = connection.cursor()

    try:
        # Delete user data from DailyLog, Reward, LogRecommendation, Recommendation, and other tables
        cursor.execute("DELETE FROM DailyLog WHERE user_id = %s", (session['user_id'],))
        cursor.execute("DELETE FROM Reward WHERE user_id = %s", (session['user_id'],))
        cursor.execute("DELETE FROM LogRecommendation WHERE user_id = %s", (session['user_id'],))
        cursor.execute("DELETE FROM Recommendation WHERE user_id = %s", (session['user_id'],))
        cursor.execute("DELETE FROM User WHERE user_id = %s", (session['user_id'],))

        connection.commit()

        # Logout the user after account deletion
        session.pop('user_id', None)
        return jsonify({'success': True, 'message': 'User account deleted successfully'}), 200
    except Exception as e:
        connection.rollback()
        logging.error("Error deleting user account:", e)
        return jsonify({'success': False, 'message': 'Failed to delete user account'}), 500
    finally:
        cursor.close()
        connection.close()

# Leaderboard Route
@app.route('/leaderboard', methods=['GET'])
def get_leaderboard():
    """Return leaderboard data."""
    connection = connect_to_db()
    cursor = connection.cursor()

    try:
        # Call stored procedure
        logging.info('Calling stored procedure GetUserLeaderboard...')
        cursor.callproc('GetUserLeaderboard')

        # Fetch the result from the stored procedure
        result = cursor.fetchall()

        logging.info(f"Leaderboard data fetched successfully: {result}")
        return jsonify(result), 200

    except Exception as e:
        logging.error(f"Error fetching leaderboard: {e}")
        return jsonify({"error": "Error fetching leaderboard"}), 500

    finally:
        cursor.close()
        connection.close()


# Mental Health Assessment Route
@app.route('/mental_health_assessment', methods=['POST'])
def submit_assessment():
    """Submit mental health assessment."""
    if not check_user_logged_in():
        return jsonify({'success': False, 'message': 'User not logged in'}), 401

    data = request.json
    user_id = session['user_id']

    connection = connect_to_db()
    cursor = connection.cursor()

    try:
        cursor.execute("SELECT COALESCE(MAX(assessment_id), 0) + 1 AS next_id FROM MentalHealthAssessment")
        next_assessment_id = cursor.fetchone()['next_id']

        cursor.execute("""
            INSERT INTO MentalHealthAssessment (assessment_id, user_id, sleep, appetite, interest, fatigue, 
                                                worthlessness, concentration, agitation, suicidal_ideation)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (next_assessment_id, user_id, data['sleep'], data['appetite'], data['interest'], data['fatigue'], 
              data['worthlessness'], data['concentration'], data['agitation'], data['suicidal_ideation']))
        

        connection.commit()
        return jsonify({'success': True, 'message': 'Assessment submitted successfully'}), 201

    except Exception as e:
        connection.rollback()
        logging.error(f"Error submitting assessment: {e}")
        return jsonify({'success': False, 'message': 'Failed to submit assessment'}), 500

    finally:
        cursor.close()
        connection.close()

@app.route('/find_friends', methods=['GET'])
def find_friends():
    """Search for users by username and return their total reward points."""
    if not check_user_logged_in():
        return jsonify({'success': False, 'message': 'User not logged in'}), 401

    search_query = request.args.get('query', '')

    if not search_query:
        return jsonify({'success': False, 'message': 'Search query is missing'}), 400

    connection = connect_to_db()
    cursor = connection.cursor()

    try:
        # Search users by username and aggregate total rewards for each user
        cursor.execute("""
            SELECT u.user_id, u.username, COALESCE(SUM(r.points), 0) AS total_rewards
            FROM User u
            LEFT JOIN Reward r ON u.user_id = r.user_id
            WHERE u.username LIKE %s 
            AND u.user_id != %s
            GROUP BY u.user_id
        """, (f"%{search_query}%", session['user_id']))

        users = cursor.fetchall()

        return jsonify({'success': True, 'users': users}), 200

    except Exception as e:
        logging.error(f"Error finding friends: {e}")
        return jsonify({'success': False, 'message': 'Failed to search for friends'}), 500

    finally:
        cursor.close()
        connection.close()


@app.route('/friend_progress/<int:user_id>', methods=['GET'])
def friend_progress(user_id):
    """View a friend's progress by user_id."""
    if not check_user_logged_in():
        return jsonify({'success': False, 'message': 'User not logged in'}), 401

    connection = connect_to_db()
    cursor = connection.cursor()

    try:
        cursor.execute("""
            SELECT dl.screen_time, dl.sleep_hours, dl.physical_activity_hours, 
                   dl.date, r.points 
            FROM DailyLog dl 
            JOIN Reward r ON dl.user_id = r.user_id 
            WHERE dl.user_id = %s
        """, (user_id,))

        progress = cursor.fetchall()

        return jsonify({'success': True, 'progress': progress}), 200

    except Exception as e:
        logging.error(f"Error fetching friend's progress: {e}")
        return jsonify({'success': False, 'message': 'Failed to fetch progress'}), 500

    finally:
        cursor.close()
        connection.close()



if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001)
