from dbconf import Conf

conf = Conf()
# conf.confSys()
db = conf.DBConf()



class Invoice(db.Model):
	__bind_key__ = 'vpnManager'
	__tablename__ = 'invoice'
	id=db.Column(db.Integer, primary_key=True)
	detail=db.Column(db.String(100))
	idClient=db.Column(db.String(50))
	price=db.Column(db.Float)
	tax=db.Column(db.Float)
	prO=db.Column(db.Float)
	taO=db.Column(db.Float)
	status=db.Column(db.Boolean)
	fechaCreacion=db.Column(db.Datetime)




# class invoice:
# 	def __init__(self,
# id,detail,idClient,price,tax,prO,taO,status,fechaCreacion):
# 		self.id=id
# 		self.detail=detail
# 		self.idClient=idClient
# 		self.price=price
# 		self.tax=tax
# 		self.prO=prO
# 		self.taO=taO
# 		self.status=status
# 		self.fechaCreacion=fechaCreacion
