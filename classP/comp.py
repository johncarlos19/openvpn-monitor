from dbconf import Conf

conf = Conf()
# conf.confSys()
db = conf.DBConf()


class Comp(db.Model):
    __bind_key__ = 'vpnManager'
    __tablename__ = 'comp'
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(50))
    documento = db.Column(db.String(20))
    nombreComercial = db.Column(db.String(50))
    telefono = db.Column(db.String(50))
    email = db.Column(db.String(50))

# class comp:
# 	def __init__(self,
# id,nombre,documento,nombreComercial,telefono,email):
# 		self.id=id
# 		self.nombre=nombre
# 		self.documento=documento
# 		self.nombreComercial=nombreComercial
# 		self.telefono=telefono
# 		self.email=email
