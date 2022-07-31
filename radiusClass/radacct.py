from dbconf import Conf

conf = Conf()
# conf.confSys()
db = conf.DBConf()

class Radacct(db.Model):

		radacctid=db.Column(db.Integer, primary_key=True)
		acctsessionid=db.Column(db.Text)
		acctuniqueid=db.Column(db.Text)
		username=db.Column(db.Text)
		groupname=db.Column(db.Text)
		realm=db.Column(db.Text)
		nasipaddress=db.Column(db.String(30))
		nasportid=db.Column(db.Text)
		nasporttype=db.Column(db.Text)
		acctstarttime=db.Column(db.DateTime)
		acctupdatetime=db.Column(db.DateTime)
		acctstoptime=db.Column(db.DateTime)
		acctinterval=db.Column(db.Integer)
		acctsessiontime=db.Column(db.Integer)
		acctauthentic=db.Column(db.Text)
		connectinfo_start=db.Column(db.Text)
		connectinfo_stop=db.Column(db.Text)
		acctinputoctets=db.Column(db.Integer)
		acctoutputoctets=db.Column(db.Integer)
		calledstationid=db.Column(db.Text)
		callingstationid=db.Column(db.Text)
		acctterminatecause=db.Column(db.Text)
		servicetype=db.Column(db.Text)
		framedprotocol=db.Column(db.Text)
		framedipaddress=db.Column(db.String(30))

# class Radacct:
# 	def __init__(self,
# radacctid,acctsessionid,acctuniqueid,username,groupname,realm,nasipaddress,nasportid,nasporttype,acctstarttime,acctupdatetime,acctstoptime,acctinterval,acctsessiontime,acctauthentic,connectinfo_start,connectinfo_stop,acctinputoctets,acctoutputoctets,calledstationid,callingstationid,acctterminatecause,servicetype,framedprotocol,framedipaddress):
# 		self.radacctid=radacctid
# 		self.acctsessionid=acctsessionid
# 		self.acctuniqueid=acctuniqueid
# 		self.username=username
# 		self.groupname=groupname
# 		self.realm=realm
# 		self.nasipaddress=nasipaddress
# 		self.nasportid=nasportid
# 		self.nasporttype=nasporttype
# 		self.acctstarttime=acctstarttime
# 		self.acctupdatetime=acctupdatetime
# 		self.acctstoptime=acctstoptime
# 		self.acctinterval=acctinterval
# 		self.acctsessiontime=acctsessiontime
# 		self.acctauthentic=acctauthentic
# 		self.connectinfo_start=connectinfo_start
# 		self.connectinfo_stop=connectinfo_stop
# 		self.acctinputoctets=acctinputoctets
# 		self.acctoutputoctets=acctoutputoctets
# 		self.calledstationid=calledstationid
# 		self.callingstationid=callingstationid
# 		self.acctterminatecause=acctterminatecause
# 		self.servicetype=servicetype
# 		self.framedprotocol=framedprotocol
# 		self.framedipaddress=framedipaddress