from flask import Flask,request,render_template,url_for,jsonify,redirect,flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.ext.declarative import DeclarativeMeta

username = "postgres"
password = "castillo30"
dbname = "radius"
dbname2 = "vpnManager"
domain = "20.124.105.127"
port = "5432"
def myGlovalFun():
  global app
  global db


myGlovalFun()

class Conf:
    myGlovalFun()
    
# app.config['SECRET_KEY'] = 'thisissecret'
# our database uri
    # app = Flask(__name__)
    # username = "postgres"
    # password = "castillo30"
    # dbname = "radius"
    # dbname2 = "vpnManager"
    # domain = "20.124.105.127"
    # port = "5432"

        
        # self.username = "postgres"
        # self.password = "castillo30"
        # self.dbname = "radius"
        # self.dbname2 = "vpnManager"
        # self.domain = "20.124.105.127"
        # self.port = "5432"
        


    def confSys(self):
        global db
        global app

        app = Flask(__name__)
        app.config["SQLALCHEMY_DATABASE_URI"] = f"postgresql://{username}:{password}@{domain}:{port}/{dbname}"
        app.config["SQLALCHEMY_BINDS"] = {
        dbname2:        f"postgresql://{username}:{password}@{domain}:{port}/{dbname2}"
    }
        db = SQLAlchemy(app)
        return
    def FlaskConf(self):
        return app
    def DBConf(self):
        return db