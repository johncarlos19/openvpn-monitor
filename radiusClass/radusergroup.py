
from dbconf import Conf

conf = Conf()
# conf.confSys()
db = conf.DBConf()



class Radusergroup(db.Model):
	id=db.Column(db.Integer, primary_key=True)
	username=db.Column(db.Text)
	groupname=db.Column(db.Text)
	priority=db.Column(db.Integer)





# class radusergroup:
# 	def __init__(self,
# id,username,groupname,priority):
# 		self.id=id
# 		self.username=username
# 		self.groupname=groupname
# 		self.priority=priority
