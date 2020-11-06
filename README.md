# dashboard

Create virtual enviorment
```
virtualenv venv
or
python3 -m venv venv
```
Activate virtual enviorment
```
source venv/bin/activate
```
Install required modules
```
pip install -r requirements
```
place the .env file as dashboard/.env and add database details such as 
NAME
DBUSER
PASSWORD
HOST
PORT
JWTTOKEN

Run migrations
```
python manage.py makemigrations
python manage.py migrate
```

Run application
```
python manage.py runserver
```

List of api's
1. signup(post)
2. login(post)
3. projects(post, get)
4. tasks(post, put)