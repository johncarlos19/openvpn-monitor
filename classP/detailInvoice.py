from dbconf import Conf

conf = Conf()
# conf.confSys()
db = conf.DBConf()


class DetailInvoice(db.Model):
	__bind_key__ = 'vpnManager'
	__tablename__ = 'detailInvoice'
	id=db.Column(db.Integer, primary_key=True)
	nombre=db.Column(db.String(50))
	descripcion=db.Column(db.String(100))
	typePack=db.Column(db.Integer)
	dataUsage=db.Column(db.Integer)
	price=db.Column(db.Float)
	tax=db.Column(db.Float)
	day=db.Column(db.Integer)
	prO=db.Column(db.Float)
	taO=db.Column(db.Float)
	idInvoice=db.Column(db.Integer)

		# class detailInvoice:
		# 	def __init__(self,
		# 				 id, nombre, descripcion, typePack, dataUsage, price, tax, day, prO, taO, idInvoice):
		# 		self.id = id
		# 		self.nombre = nombre
		# 		self.descripcion = descripcion
		# 		self.typePack = typePack
		# 		self.dataUsage = dataUsage
		# 		self.price = price
		# 		self.tax = tax
		# 		self.day = day
		# 		self.prO = prO
		# 		self.taO = taO
		# 		self.idInvoice = idInvoice
