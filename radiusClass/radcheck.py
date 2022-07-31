from dbconf import Conf

conf = Conf()
# conf.confSys()
db = conf.DBConf()
class Radcheck(db.Model):
	id=db.Column(db.Integer, primary_key=True)
	username=db.Column(db.Text)
	attribute=db.Column(db.Text)
	op=db.Column(db.String(2))
	value=db.Column(db.Text)
	status=db.Column(db.Boolean)
	expDate=db.Column(db.DateTime)
	maxDataUsage=db.Column(db.Integer)


# class radcheck:
# 	def __init__(self,
# id,username,attribute,op,value,status,expDate,maxDataUsage):
# 		self.id=id
# 		self.username=username
# 		self.attribute=attribute
# 		self.op=op
# 		self.value=value
# 		self.status=status
# 		self.expDate=expDate
# 		self.maxDataUsage=maxDataUsage
