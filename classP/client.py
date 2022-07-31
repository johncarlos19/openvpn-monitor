from dbconf import Conf

conf = Conf()
# conf.confSys()
db = conf.DBConf()


class Client(db.Model):
	__bind_key__ = 'vpnManager'
	user=db.Column(db.String(50), primary_key=True)
	nombre=db.Column(db.String(50))
	apellido=db.Column(db.String(50))
	documento=db.Column(db.String(20))
	fechaNacimiento=db.Column(db.DateTime)
	status=db.Column(db.Boolean)
	password=db.Column(db.String(255))
	FechaCreacion=db.Column(db.DateTime)
	fechaExpiracion=db.Column(db.DateTime)
	DataMaxUse=db.Column(db.Integer)
	idVPN=db.Column(db.Integer)
	idPackPrincipal=db.Column(db.Integer)
	typeClient=db.Column(db.String(3))
	userAdm=db.Column(db.String(50))
	idvpnServerDefault=db.Column(db.Integer)



# class client:
# 	def __init__(self,
# user,nombre,apellido,documento,fechaNacimiento,status,password,FechaCreacion,fechaExpiracion,DataMaxUse,idVPN,idPackPrincipal,typeClient,userAdm,idvpnServerDefault):
# 		self.user=user
# 		self.nombre=nombre
# 		self.apellido=apellido
# 		self.documento=documento
# 		self.fechaNacimiento=fechaNacimiento
# 		self.status=status
# 		self.password=password
# 		self.FechaCreacion=FechaCreacion
# 		self.fechaExpiracion=fechaExpiracion
# 		self.DataMaxUse=DataMaxUse
# 		self.idVPN=idVPN
# 		self.idPackPrincipal=idPackPrincipal
# 		self.typeClient=typeClient
# 		self.userAdm=userAdm
# 		self.idvpnServerDefault=idvpnServerDefault
