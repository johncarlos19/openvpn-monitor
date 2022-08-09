from dbconf import Conf

conf = Conf()
# conf.confSys()
db = conf.DBConf()


class ClientPackSubcription(db.Model):
    __bind_key__ = 'vpnManager'
    __tablename__ = 'ClientPackSubcription'
    userClient = db.Column(db.String(50), primary_key=True)
    idPack = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.Integer)
    exp = db.Column(db.DateTime)
    isTemporary = db.Column(db.Boolean, default= False)


# class ClientPackSubcription:
#     def __init__(self,
#                  userClient, idPack, type):
#         self.userClient = userClient
#         self.idPack = idPack
#         self.type = type
