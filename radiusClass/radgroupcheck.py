from dbconf import Conf

conf = Conf()
# conf.confSys()
db = conf.DBConf()



class Radgroupcheck(db.Model):
	id=db.Column(db.Integer, primary_key=True)
	groupname=db.Column(db.Text)
	attribute=db.Column(db.Text)
	op=db.Column(db.String(2))
	value=db.Column(db.Text)



# class radgroupcheck:
# 	def __init__(self,
# id,groupname,attribute,op,value):
# 		self.id=id
# 		self.groupname=groupname
# 		self.attribute=attribute
# 		self.op=op
# 		self.value=value
