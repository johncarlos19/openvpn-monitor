
from dbconf import Conf

conf = Conf()
# conf.confSys()
db = conf.DBConf()
class Nas(db.Model):
    __tablename__ = 'nas'
    id=db.Column(db.Integer, primary_key=True)
    nasname=db.Column(db.Text)
    shortname=db.Column(db.Text)
    type=db.Column(db.Text)
    ports=db.Column(db.Integer)
    secret=db.Column(db.Text)
    server=db.Column(db.Text)
    community=db.Column(db.Text)
    description=db.Column(db.Text)

# class nas:
# 	def __init__(self,
# id,nasname,shortname,type,ports,secret,server,community,description):
# 		self.id=id
# 		self.nasname=nasname
# 		self.shortname=shortname
# 		self.type=type
# 		self.ports=ports
# 		self.secret=secret
# 		self.server=server
# 		self.community=community
# 		self.description=description
