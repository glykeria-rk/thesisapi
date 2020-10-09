import os
import peewee
import dateutil.rrule as rrule
import datetime
import json
import typing
import bcrypt
import pickle
import config
from exceptions import UserDoesNotExist
from exceptions import WrongPasswordException
from exceptions import EmailAddressAlreadyExists
from exceptions import ItemDoesNotExistException


class PickledField(peewee.BlobField):
    def db_value(self, value):
        if value is not None:
            return pickle.dumps(value)

    def python_value(self, value):
        if value is not None:
            return pickle.loads(value)


class DateTimeBlockList(list):
    def datetime_in_block_list(self, dt) -> bool:
        for datetime_block in self:
            if datetime_block.datetime_in_block(dt):
                return True
        return False


class DateTimeBlock:
    def __init__(self, start_dt: datetime.datetime, end_dt: datetime.datetime, rrule_str: str):
        self.start_dt = start_dt
        self.end_dt = end_dt
        self.rrule_str = rrule_str

    @property
    def ranges(self) -> typing.List[typing.Tuple[datetime.datetime, datetime.datetime]]:
        """
        This applies the rrule with the start dt
        as an argument to result in a list of ranges,
        which is easier to work with.
        """
        if not self.rrule_str:
            return [(self.start_dt, self.end_dt)]

        return list(zip(list(self.start_dt_rrule), list(self.end_dt_rrule)))
        # return list(zip(list(rrule(self.rrule_frequency, dtstart=self.start_dt, **self.rrule_options)), list(rrule(self.rrule_frequency,  dtstart=self.end_dt, **self.rrule_options))))

    @property
    def rrule(self):
        return rrule.rrulestr(self.rrule_str) if self.rrule_str else None

    @property
    def start_dt_rrule(self):
        start_dt_rrule = rrule.rrulestr(
            self.rrule_str)
            
        start_dt_rrule.start_dt = self.start_dt
        return start_dt_rrule

    @property
    def end_dt_rrule(self):
        end_dt_rrule = rrule.rrulestr(self.rrule_str)
        end_dt_rrule.end_dt = self.end_dt
        return end_dt_rrule

    @property
    def frequency(self):
        if not self.rrule or not self.rrule._freq: return None
        FREQNAMES = ['YEARLY', 'MONTHLY', 'WEEKLY', 'DAILY', 'HOURLY', 'MINUTELY', 'SECONDLY']
        return FREQNAMES[self.rrule._freq]

    @property
    def until(self):
        return self.start_dt_rrule._until if self.rrule else None

    @property
    def count(self):
        return self.start_dt_rrule._count if self.rrule else None

    def datetime_in_block(self, dt: datetime.datetime) -> bool:
        """
        """
        for begin, end in self.ranges:
            if begin <= dt <= end:
                return True
        return False

    def __str__(self):
        pass


if True:
    username = os.environ.get("MYSQL_USERNAME")
    password = os.environ.get("MYSQL_PASSWORD")
    #print(username)
    #print(password)
    database = peewee.MySQLDatabase(database="thesislock", user=username, password=password, host="127.0.0.1", port=3306)
#else:
#    database = peewee.MySQLDatabase("thesislock", user="api", password="koDx9xSfp", unix_socket="/cloudsql/thesis-lock:europe-west1:thesis-lock")


class BaseModel(peewee.Model):
    class Meta:
        database = database


class User(BaseModel):
    email_address = peewee.CharField(
        max_length=55, unique=True, index=True, primary_key=True, null=False)
    password = peewee.CharField(max_length=255, null=True)
    is_admin = peewee.BooleanField(default=False)
    rfid_id = peewee.CharField(max_length=55, null=True, unique=True)
    datetime_ranges = PickledField(null=False, default=DateTimeBlockList())
    access_status = peewee.CharField(choices=[(
        'deny', 'Deny'), ('access_rules', 'Access rules'), ('grant', 'Grant')], default='access_rules')

    def deny_unconditional_access(self):
        self.access_status = 'deny'
        self.save()

    def grant_unconditional_access(self):
        self.access_status = 'grant'
        self.save()

    def use_access_rules(self):
        self.access_status = 'access_rules'
        self.save()

    def add_new_datetime_range(self, dt_block: DateTimeBlock) -> bool:
        """
        Check for overlap

        Return True if successful
        """
        self.datetime_ranges.append(dt_block)
        self.save()
        return True

    def remove_datetime_range(self, index) -> bool:
        """
        Remove a datetime range/access rule
        by index.
        """
        try:
            del self.datetime_ranges[index]
        except IndexError:
            raise ItemDoesNotExistException
        self.save()
        return True

    def currently_has_access(self) -> bool:
        """
        Go through all the blocks and call their
        datetime_in_block method.
        """
        if self.access_status == 'grant':
            return True
        if self.access_status == 'deny':
            return False
        return self.datetime_ranges.datetime_in_block_list(datetime.datetime.now())

    def set_password(self, plaintext_password):
        hashed_password = bcrypt.hashpw(
            plaintext_password.encode('utf-8'), bcrypt.gensalt(config.BCRYPT_WORK_FACTOR))
        self.password = hashed_password.decode('utf8')
        self.save()

    def verify_password(self, plaintext_password):
        print(plaintext_password)
        print(self.password)
        return bcrypt.checkpw(plaintext_password.encode('utf8'), self.password.encode('utf8'))

    def assign_rfid_id(self, rfid_id):
        self.rfid_id = rfid_id
        self.save()

    def remove_rfid_id(self):
        self.rfid_id = None
        self.save()

    @classmethod
    def login(cls, email_address, plaintext_password):
        try:
            user = cls.get(email_address=email_address)
        except cls.DoesNotExist:
            raise UserDoesNotExist

        if not user.verify_password(plaintext_password):
            raise WrongPasswordException

        return user

    @classmethod
    def signup(cls, email_address, plaintext_password):
        try:
            user = cls.create(email_address=email_address)
        except peewee.IntegrityError:
            raise EmailAddressAlreadyExists

        user.set_password(plaintext_password)

        return user

    @classmethod
    def by_email_address(cls, email_address):
        try:
            user = cls.get(email_address=email_address)
        except User.DoesNotExist:
            raise UserDoesNotExist

        return user


class Log(BaseModel):
    user = peewee.ForeignKeyField(User, related_name = 'logs', null=True)
    category = peewee.CharField(
        choices=[('lock_opened', 'Lock opened'), ('access_denied', 'Access denied'), ('unknown_tag', 'Unknown tag')], null=False) 
    method = peewee.CharField(
        choices=[('qr', 'QR-code'), ('nfc', 'NFC')], null=False) 
    dt = peewee.DateTimeField(default=datetime.datetime.now, null=False)
