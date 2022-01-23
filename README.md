# Development

Following are instructions on setting up your development environment.
## Setup 

1. [Mysql](https://www.mysql.com//)
2. [Python](https://www.python.org/downloads/release/python-365/)
2. [Redis](https://redis.io/)

### Installation
- Clone this repo and `cd /django-backend-app`
### 1:-  Database migrations

### 2:- Create Virtual Enviroment and active your enviroment
- RUN :- `python3 -m venv djangoVenv`
- RUN :- `source djangoVenv/bin/activate`

### 3:- Install requirements on you enviroment
- RUN :- `pip3 install -r requirements.txt`
- Check all requirements installed or not using CMD : `pip3 freeze`

### 4:- RUN application :
- RUN :- `python3 manage.py run :-server`

### Backend Coding System:
- `admin_cms` This dir using for all admins parts api like create admin login and view all of the admin management sytem from this.This is the admin of the app.
- `app` This is the common app of project.
- `common_util` This is the common utils helper for the all of the project.
- `customer_app` This is the main client side app you can change name of this from you project basis .This is the all backend part for the customer side app
- `server_setup` This is the database configuration and db migration and some other depencdices helper you can run for this sh for setup project on your server.