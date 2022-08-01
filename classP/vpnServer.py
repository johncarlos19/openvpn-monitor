from dbconf import Conf

conf = Conf()
# conf.confSys()
db = conf.DBConf()


class VpnServer(db.Model):
    __bind_key__ = 'vpnManager'
    __tablename__ = 'vpnServer'
    id = db.Column(db.Integer, primary_key=True)
    host = db.Column(db.String(20))
    port = db.Column(db.Integer)
    name = db.Column(db.String(50))
    password = db.Column(db.String(50))
    show_disconnect = db.Column(db.Boolean)
    maxRegister = db.Column(db.Integer)
    clientActive = db.Column(db.Integer)
    clientRegister = db.Column(db.Integer)


# class vpnServer:
# 	def __init__(self,
# id,host,port,name,password,show_disconnect,maxRegister,clientActive,clientRegister):
# 		self.id=id
# 		self.host=host
# 		self.port=port
# 		self.name=name
# 		self.password=password
# 		self.show_disconnect=show_disconnect
# 		self.maxRegister=maxRegister
# 		self.clientActive=clientActive
# 		self.clientRegister=clientRegister
