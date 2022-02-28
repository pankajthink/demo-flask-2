virtualenv env
source env/bin/activate
pip install -r requirements.txt


run the following command in terminal
export FLASK_APP=app.py
flask run   			//for running flask app


-------------------data base set up--------------------------------
Create database Flask_task_db1;
CREATE USER 'Flask_task_user1'@'localhost' IDENTIFIED BY 'Pass123';
GRANT ALL ON Flask_task_db1.* TO 'Flask_task_user1'@'localhost';
FLUSH PRIVILEGES;


pip install flask_mysqldb
sudo apt-get install libmysqlclient-dev			// use this cmd only if you get error while running above command.


Flask_task_user
Flask_task_db
Flask@123
root
localhost

# for sqlite database
Next you need to type the following in your python or python3 in your terminal then run below 2 commands:
from app import db
db.create_all()

So, what this does is first it imports the database object and then calls the create_all() function to create all the tables from the ORM.

# for mysql db
flask db init
flask db migrate -m "Initial migration."
flask db upgrade
