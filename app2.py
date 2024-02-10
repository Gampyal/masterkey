from flask import Flask, redirect, render_template, request, url_for
import mysql.connector

app = Flask(__name__)

db = mysql.connector.connect(
    host="localhost",
    user="root",
    password="newagemongodb",
    database="bincompythontest"
)

myCursor = db.cursor()



@app.route('/new_polling_unit', methods=['GET', 'POST'])
def create_polling_unit():
    if request.method == 'POST':
        n_polling_unit_id = request.form['n_polling_unit_id']
        n_ward_id = request.form['n_ward_id']
        n_lga_id = request.form['n_lga_id']
        n_uniquewardid = request.form['n_uniquewardid']
        n_polling_unit_number = request.form['n_polling_unit_number']
        n_polling_unit_name = request.form['n_polling_unit_name']
        n_polling_unit_description = request.form['n_polling_unit_description']
        n_lat = request.form['n_lat']
        n_long = request.form['n_long']
        n_entered_by_user = request.form['n_entered_by_user']
        n_date_entered = request.form['n_date_entered']
        n_user_ip_address = request.form['n_user_ip_address']


        try:
            query = f"INSERT INTO polling_unit (polling_unit_id, ward_id, lga_id, uniquewardid, polling_unit_number, polling_unit_name, polling_unit_description, lat, long, entered_by_user, date_entered, user_ip_address) VALUES ({n_polling_unit_id}, {n_ward_id}, {n_lga_id}, {n_uniquewardid}, {n_polling_unit_number}, {n_polling_unit_name}, {n_polling_unit_description}, {n_lat}, {n_long}, {n_entered_by_user}, {n_date_entered}, {n_user_ip_address})"

            myCursor.execute(query)
            db.commit()


            myCursor.execute("SELECT uniqueid FROM polling_unit ORDER BY uniqueid DESC LIMIT 1")
            puuid = myCursor.fetchone()[0]
            return redirect(url_for('upload_results', polling_unit_id=puuid))
    
        except Exception as e:
            db.rollback()
            return f"Error: {e}"
        

    return render_template('new_polling_unit.html')
   





@app.route('/upload_results/<int:polling_unit_id>', methods=['GET', 'POST'])
def upload_results(polling_unit_id):
    # Fetch party names
    myCursor.execute("SELECT partyname FROM party")
    party_names = [result[0] for result in myCursor.fetchall()]

    # Process party names to get abbreviations
    party_abbreviations = [name[:4] for name in party_names]

    # Initialize party_scores dictionary
    party_scores = {}

    # Loop through party abbreviations
    for party_abbr in party_abbreviations:
        score = int(request.form.get(f'score_{party_abbr}'))
        party_scores[party_abbr] = score

    # Prompt user for additional information
    pu_results_entered_by_user = request.form.get('entered_by_user', 'NULL')
    pu_results_date_entered = request.form.get('date_entered', 'NULL')
    pu_results_user_ip_address = request.form.get('user_ip_address', 'NULL')

    try:
        # Generate and Execute INSERT Queries
        for party_abbr, score in party_scores.items():
            insert_query = f"INSERT INTO announced_pu_results (polling_unit_uniqueid, party_abbreviation, party_score, entered_by_user, date_entered, user_ip_address) VALUES ({polling_unit_id}, '{party_abbr}', {score}, '{pu_results_entered_by_user}', '{pu_results_date_entered}', '{pu_results_user_ip_address}')"
            
            myCursor.execute(insert_query)
            db.commit()

        return "Results entered successfully!"
    except Exception as e:
        db.rollback()
        return f"Error: {e}"








myCursor.close()
db.close()
if __name__ == '__main__':
    app.run(debug=True)
