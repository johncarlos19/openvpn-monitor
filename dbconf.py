import os
from flask import Flask,send_file, send_from_directory,session,request,render_template,url_for,jsonify,redirect,flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.ext.declarative import DeclarativeMeta

import datetime



from encrypt import AESCipher

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
        global engine
        encrypt = AESCipher(b'zM6WNtrCoFMa3cNkGy2p9Yw1RGB-JJD4nlwZy4121MI=')
        app = Flask(__name__)
        app.secret_key = os.urandom(25)
        app.config["SQLALCHEMY_DATABASE_URI"] = f"postgresql://{username}:{password}@{domain}:{port}/{dbname}"
        app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
        app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {"pool_pre_ping": True, "pool_size": 10, "max_overflow": 2, "pool_recycle": 300, "pool_use_lifo": True}
        app.config["SQLALCHEMY_BINDS"] = {
        dbname2:        f"postgresql://{username}:{password}@{domain}:{port}/{dbname2}"}
        db = SQLAlchemy(app)

        from classP.administrador import Administrador
        from classP.client import Client
        from radiusClass.radcheck import Radcheck
        datetime_object = datetime.datetime.now()
        adm = Administrador.query.filter_by(usuario='admin').first()
        if adm is None:
            au = Administrador(
		usuario='admin',
		nombre='Administrador',
		apellido='',
		typeUser='ADM',
		documento='1234567890',
		estado=True,
		password=encrypt.encrypt({"password":"admin1234"}),
		fakeInvoice=True
                )
            db.session.add(au)
            db.session.flush()
            db.session.refresh(au)
            db.session.commit()
            radChe = Radcheck(username=au.usuario,
            attribute='Cleartext-Password',
            op=':=',
            value='admin1234',
            maxDataUsage=-1,
            status=True,
            expDate=datetime_object)

            db.session.add(radChe)
            db.session.flush()
            db.session.refresh(radChe)
            db.session.commit()

            clien = Client(
                user=au.usuario,
                nombre=au.nombre,
                apellido=au.apellido,
                documento=au.documento,
                fechaNacimiento=datetime_object,
                FechaCreacion=datetime_object,
                fechaExpiracion=datetime_object,
                password=au.password,
                status=True,
                DataMaxUse=-1,
                idVPN=radChe.id,
                idPackPrincipal=-1,
                typeClient='ADM',
                userAdm=au.usuario,
                idvpnServerDefault=0
                )
            db.session.add(clien)
            db.session.flush()
            db.session.refresh(clien)
            db.session.commit()

                
        else:
            print(encrypt.decrypt(adm.password))
            print('Existe')


        
        return
    def FlaskConf(self):
        return app
    def DBConf(self):
        return db