from dbconf import Conf

conf = Conf()
# conf.confSys()
db = conf.DBConf()



class Administrador(db.Model):
	__bind_key__ = 'vpnManager'
	__tablename__ = 'administrador'
	usuario=db.Column(db.String(50), primary_key=True)
	nombre=db.Column(db.String(50))
	apellido=db.Column(db.String(50))
	email=db.Column(db.String(50))
	typeUser=db.Column(db.String(3))
	documento=db.Column(db.String(20))
	estado=db.Column(db.Boolean)
	password=db.Column(db.Text)
	fakeInvoice=db.Column(db.Boolean)




# class administrador:
# 	def __init__(self,
# usuario,nombre,apellido,typeUser,documento,estado,password,fakeInvoice):
# 		self.usuario=usuario
# 		self.nombre=nombre
# 		self.apellido=apellido
# 		self.typeUser=typeUser
# 		self.documento=documento
# 		self.estado=estado
# 		self.password=password
# 		self.fakeInvoice=fakeInvoice

