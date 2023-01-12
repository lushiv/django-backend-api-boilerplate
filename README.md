# Django Backend REST API Boilarplate With MYSQL:-
## Development
## Setup 
1. [Mysql](https://www.mysql.com//)
2. [Python](https://www.python.org/downloads/release/python-365/)
2. [Redis](https://redis.io/)


## Get Start Installation:-
Following are instructions on setting up your development environment.

- Clone this repo and `cd /django-backend-app`
## 1:-  Database migrations:
We are using liquibase base for the db migration process so we need something idea about liquibase.If You want more about liquibase you can go from this [link](#).
Here is the steps for setup and run the db_migrations file:
- Go the cd `cd /django-backend-app/server_setup/db_migrations`
- RUN `chmod +x deploy_db.sh`
- RUN `./deploy_db.sh`

But if your setup first time setup please check the this steps:
```
changeLogFile: customer/changelog-master.xml
driver: com.mysql.cj.jdbc.Driver
url: jdbc:mysql://localhost:3306/django_database?autoReconnect=true&useSSL=false&maxReconnects=10&allowPublicKeyRetrieval=true&createDatabaseIfNotExist=true
username: root
password: Mobile@97701
logLevel=DEBUG
classpath: ./mysql-connector-java-8.0.19.jar

```
- verify `username` and `password` of your MySql in `liquibase.properties` file from both `admin` & `customer`

## 2:- Create Virtual Enviroment and active your enviroment
- RUN :- `python3 -m venv djangoVenv`
- RUN :- `source djangoVenv/bin/activate`

## 3:- Install requirements on you enviroment
- RUN :- `pip3 install -r requirements.txt`
- Check all requirements installed or not using CMD : `pip3 freeze`

## 4:-  Logger Path Setup:
Dont forgot to ccreate the path for logger.
- First you need to make `configuration.ini` file using `configuration_prod.ini`
- Then check the all configs on that file.
```
[common_logs]
path = logs/customer-logs
category = customer

[admin_logs]
path = logs/admin-logs
category = admin

```
You need to create this types of path on your current working dir : `logs/common-logs` & `logs/admin-logs`

## 5:- RUN application :
- RUN :- `python3 manage.py run :-server`

## Folder Strucures:
- `admin_cms` This dir using for all admins parts api like create admin login and view all of the admin management sytem from this.This is the admin of the app.
- `app` This is the common app of project.
- `common_util` This is the common utils helper for the all of the project.
- `customer_app` This is the main client side app you can change name of this from you project basis .This is the all backend part for the customer side app
- `server_setup` This is the database configuration and db migration and some other depencdices helper you can run for this sh for setup project on your server.