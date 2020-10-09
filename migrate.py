from playhouse.migrate import *
from models import database
from models import User
from models import Log
import peewee

migrator = MySQLMigrator(database)

if __name__ == '__main__':
    Log.drop_table()
    Log.create_table()
    
   # migrate(migrator.drop_column('user', 'password'), migrator.add_column('user', 'password', peewee.CharField(max_length=255, null=True)))
    #migrate(migrator.add_column('user', 'access_status', peewee.CharField(choices=[('deny', 'Deny'), ('access_rules', 'Access rules'), ('grant', 'Grant')], default='access_rules')))
