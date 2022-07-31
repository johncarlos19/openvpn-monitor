from dbconf import Conf

conf = Conf()
# conf.confSys()
db = conf.DBConf()



class Radpostauth(db.Model):
	id=db.Column(db.Integer, primary_key=True)
	username=db.Column(db.Text)
	_pass=db.Column(db.Text)
	reply=db.Column(db.Text)
	calledstationid=db.Column(db.Text)
	callingstationid=db.Column(db.Text)
	authdate=db.Column(db.DateTime)
# class radpostauth:
# 	def __init__(self,
# id,username,_pass,reply,calledstationid,callingstationid,authdate):
# 		self.id=id
# 		self.username=username
# 		self._pass=_pass
# 		self.reply=reply
# 		self.calledstationid=calledstationid
# 		self.callingstationid=callingstationid
# 		self.authdate=authdate
