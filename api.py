import datetime
import typing

from dateutil.rrule import rrulestr

from flask import Flask, jsonify, request
from flask_jwt_extended import JWTManager
from flask_jwt_extended import jwt_required
from flask_jwt_extended import create_access_token
from flask_jwt_extended import create_refresh_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import decode_token

from peewee import JOIN

from models import User
from models import Log
from models import DateTimeBlock

from exceptions import UserDoesNotExist
from exceptions import WrongPasswordException
from exceptions import EmailAddressAlreadyExists
from exceptions import ItemDoesNotExistException

from decorators import pi_required, user_required, admin_required

from helpers import validate_rrule_str
from helpers import validate_and_get_dt_str

from config import DEBUG

from models import database

app = Flask(__name__)

app.config['JWT_SECRET_KEY'] = 'super-secret'  # Change this!
jwt = JWTManager(app)


@app.before_first_request
def create_tables():
    User.create_table(safe=True)
    Log.create_table(safe=True)


@app.before_request
def _db_connect():
    if not database.is_connection_usable():
        database.connect()


@app.teardown_request
def _db_close(exc):
    if not database.is_closed():
        database.close()


@jwt.user_claims_loader
def add_claims_to_access_token(user):
    return {
        'is_admin': user.is_admin,
    }


@jwt.user_identity_loader
def user_identity_lookup(user):
    return user.email_address


def get_user_from_json(request):
    """
    Response: success, value
    """
    json = request.get_json()

    if not json:
        return False, (jsonify({"status": "failed", "message": "No json payload"}), 401)

    try:
        email_address = json["email_address"]
    except KeyError:
        return False, (jsonify({"status": "failed", "message": "No email address found in json payload"}), 401)

    try:
        user = User.get(email_address=email_address)
    except User.DoesNotExist:
        return False, (jsonify({"status": "failed", "message": "No user exists with this email address"}), 400)

    return True, user

@app.route('/create-admin-user/', methods=["POST"])
# SECURE THIS!
def create_admin_user():
    if not request.is_json:
        return jsonify({"msg": "Missing JSON in request"}), 400

    email_address = request.json.get('email_address', None)
    password = request.json.get('password', None)
    if not email_address:
        return jsonify({"msg": "Missing email_address parameter"}), 400
    if not password:
        return jsonify({"msg": "Missing password parameter"}), 400

    try:
        user = User.signup(email_address, password)
    except EmailAddressAlreadyExists:
        return jsonify({"msg": "User already exists"}), 401

    user.is_admin = True
    user.save()

    return jsonify({"msg": "Admin user successfully created"}), 200


@app.route('/signup/', methods=['POST'])
def signup():
    if not request.is_json:
        return jsonify({"msg": "Missing JSON in request"}), 400

    email_address = request.json.get('email_address', None)
    password = request.json.get('password', None)
    if not email_address:
        return jsonify({"msg": "Missing email_address parameter"}), 400
    if not password:
        return jsonify({"msg": "Missing password parameter"}), 400

    try:
        user = User.signup(email_address, password)
    except EmailAddressAlreadyExists:
        return jsonify({"msg": "User already exists"}), 401

    access_token = create_access_token(identity=user)
    return jsonify(access_token=access_token), 200
    #refresh_token = create_refresh_token(identity=user)
    # return jsonify(access_token=access_token, refresh_token=refresh_token), 200


@app.route('/login/', methods=['POST'])
def login():
    if not request.is_json:
        return jsonify({"msg": "Missing JSON in request"}), 400

    email_address = request.json.get('email_address', None)
    password = request.json.get('password', None)
    if not email_address:
        return jsonify({"msg": "Missing email_address parameter"}), 400
    if not password:
        return jsonify({"msg": "Missing password parameter"}), 400

    try:
        user = User.login(email_address, password)
    except UserDoesNotExist:
        return jsonify({"msg": "Bad email address"}), 401
    except WrongPasswordException:
        return jsonify({"msg": "Bad password"}), 401

    access_token = create_access_token(identity=user)
    #refresh_token = create_refresh_token(identity=user)
    return jsonify(access_token=access_token), 200


@app.route('/users/<string:email_address>/', methods=["DELETE"])
def remove_user(email_address):
    try:
        user = User.get(email_address=email_address)
    except UserDoesNotExist:
        return jsonify({"status": "failed", "message": "User does not exist"}), 404

    user.delete_instance()

    return jsonify({"status": "success"}), 200


@app.route('/log/', methods=['GET'])
def view_log():
    logs = Log.select().join(User, JOIN.LEFT_OUTER).order_by(Log.dt.desc()).limit(10)
    print(logs)
    return jsonify({"logs": [{"category": log.category, "user": log.user.email_address if log.user is not None else None, "datetime": log.dt, "method": log.method} for log in logs]}), 200


def create_log_entry(category, method, user):
    log = Log.create(category=category, method=method, user=user)
    return jsonify({"status": "success"}), 200


@app.route("/verify-rfid-id-access/", methods=["POST"])
# PROTECT!
def verify_rfid_id_access():
    """
    Route used by the Pi to verify
    access with an RFID tag
    """
    json = request.get_json()
    try:
        rfid_id = json["rfid_id"]
    except TypeError:
        return jsonify({"status": "failed", "message": "No json payload"}), 400
    except KeyError:
        return jsonify({"status": "failed", "message": "No rfid id found in json payload"}), 401

    try:
        user = User.get(rfid_id=rfid_id)
    except User.DoesNotExist:
        create_log_entry('unknown_tag', 'nfc', None)
        return jsonify({"status": "failed", "message": "Tag not associated with user"}), 400

    if not user.currently_has_access():
        # log fail
        create_log_entry('access_denied', 'nfc', user)
        return jsonify({"status": "failed", "message": "User does not have access at the moment"}), 403

    # log success
    create_log_entry('lock_opened', 'nfc', user)
    return jsonify({"status": "success"}), 200


@app.route('/verify-qr-code-access/', methods=['POST'])
# @pi_required  PROTECT THIS
def verify_qr_code_access():
    """
    Route used by the Pi to verify
    access with a JWT encoded
    as a QR code
    """
    json = request.get_json()

    try:
        user_jwt_token_json = json["user_jwt_token"]
    except TypeError:
        return jsonify({"status": "failed", "message": "No json payload"}), 400
    except KeyError:
        return jsonify({"status": "failed", "message": "No rfid id found in json payload"}), 401

    
    user_jwt_token = decode_token(user_jwt_token_json, allow_expired=True)
    user_email = user_jwt_token["identity"]

    try:
        user = User.by_email_address(user_email)
    except UserDoesNotExist:
        return jsonify({"status": "failed", "message": "This user (no longer) exists."}), 400
    

    if not user.currently_has_access():
        # log fail
        create_log_entry('access_denied', 'qr', user)
        return jsonify({"status": "failed", "message": "User does not have access at the moment"}), 403

    # log success
    create_log_entry('lock_opened', 'qr', user)
    return jsonify({"status": "success"}), 200


@app.route("/assign-rfid-id-to-user/", methods=["POST"])
# PROTECT!
def assign_rfid_id_to_user():
    """
    Route used to assign the id
    of a physical RFID-tag
    to a user. Each user can only
    have one RFID-tag assigned to them.
    """

    success, value = get_user_from_json(request)
    if not success:
        return value
    user = value

    json = request.get_json()
    try:
        rfid_id = json["rfid_id"]
    except KeyError:
        return jsonify({"status": "failed", "message": "No rfid id found in json payload"}), 401

    user.assign_rfid_id(rfid_id)

    return jsonify({"status": "success", "message": "RFID ID successfully assigned to user"}), 200


@app.route("/remove-rfid-id-from-user/", methods=["POST"])
def remove_rfid_id_from_user():
    success, value = get_user_from_json(request)
    if not success:
        return value
    user = value

    user.remove_rfid_id()

    return jsonify({"status": "success"}), 200


@app.route("/my-rules/", methods=['GET'])
@user_required
def my_rules():
    """
    Send the rules as strings,
    which will then be made human-readable
    on the client side.
    """
    email_address = get_jwt_identity()
    user = User.get(email_address)
    return jsonify({"access_rules": user.datetime_ranges, "status": "success"}), 200


@app.route('/users/', methods=['GET'])
# @admin_required
def users():
    """
    A list of all users.
    This route currently does not use
    pagination, but this can be implemented
    later quite easily.
    """
    users = User.select()
    return jsonify([{"email_address": user.email_address, "is_admin": user.is_admin, "access_status": user.access_status, "rfid_id": user.rfid_id} for user in users]), 200


@app.route("/grant-unconditional-access/", methods=["POST"])
def grant_unconditional_access():
    """
    This route is used to grant
    unconditional access to a specific user.
    This can be used either for testing purposes
    or because the user requires unconditional access.

    This overrules all access rules that may be present!
    The user will ALWAYS have access, even if the access rules
    deny them access at the present time.
    """
    success, value = get_user_from_json(request)
    if not success:
        return value
    user = value
    user.grant_unconditional_access()
    return jsonify({"message": "Granted unrestricted access to this user"}), 200


@app.route("/deny-unconditional-access/", methods=["POST"])
def deny_unconditional_access():
    """
    This route is used to deny access to a specific user.
    This can be used either for testing purposes
    or because the user requires unconditional access.

    This overrules all access rules that may be present!
    The user will NEVER have access, even if the access 
    rules allow them to gain access at the present time.
    """
    success, value = get_user_from_json(request)
    if not success:
        return value
    user = value
    user.deny_unconditional_access()
    return jsonify({"message": "Granted unrestricted access to this user"}), 200


@app.route("/use-access-rules/", methods=["POST"])
def use_access_rules():
    """
    This route is used to use access rules to determine
    whether a user should be given access or not.

    This is the default, but it can be used after a user
    has been granted or denied unconditional access.

    If no access rules are present, the user will always
    be denied access.
    """
    success, value = get_user_from_json(request)
    if not success:
        return value
    user = value
    user.use_access_rules()
    return jsonify({"message": "Using access rules for this user"}), 200


@app.route('/users/<string:user_email_address>/access-rules/', methods=['GET'])
# @admin_required
def get_user_access_rules(user_email_address: str):
    try:
        user = User.get(email_address=user_email_address)
    except User.DoesNotExist:
        return jsonify({"status": "failed", "message": "A user with email address {} does not seem to exist.".format(user_email_address)}), 401

    return jsonify({"email_address": user.email_address, "access_rules": [{"start_dt": dt_range.start_dt, "end_dt": dt_range.end_dt, "frequency": str(dt_range.frequency), "until": str(dt_range.until), "count": str(dt_range.count)} for dt_range in user.datetime_ranges]}), 200


@app.route('/users/<string:user_email_address>/access-rules/', methods=['POST'])
# @admin_required
def add_user_access_rule(user_email_address: str):
    success, value = get_user_from_json(request)
    if not success:
        return value
    user = value

    json = request.get_json()

    try:
        start_dt_stamp = json["start_dt_stamp"]
    except KeyError:
        return jsonify({"status": "failed", "message": "No start timestamp supplied"}), 401

    try:
        end_dt_stamp = json["end_dt_stamp"]
    except KeyError:
        return jsonify({"status": "failed", "message": "No end timestamp supplied"}), 401

    success, message, start_dt = validate_and_get_dt_str(
        start_dt_stamp, "start_dt_str")
    if not success:
        return message

    success, message, end_dt = validate_and_get_dt_str(
        end_dt_stamp, "end_dt_str")
    if not success:
        return message

    try:
        rrule_str = json["rrule_str"]
    except KeyError:
        rrule_str = None

    if rrule_str:
        success, message = validate_rrule_str(rrule_str)
        if not success:
            return message, 400

    date_time_block = DateTimeBlock(
        start_dt=start_dt, end_dt=end_dt, rrule_str=rrule_str)
    successful = user.add_new_datetime_range(date_time_block)
    if successful:
        return jsonify({"status": "success"}), 200
    else:
        return jsonify({"status": "failed"}), 500


@app.route('/users/<string:email_address>/access-rules/<int:list_index>/', methods=['DELETE'])
# @admin_required
def remove_user_access_rule(email_address, list_index):
    try:
        user = User.by_email_address(email_address)
    except UserDoesNotExist:
        return jsonify({"status": "failed", "message": "User with email address does not exist"}), 401

    try:
        user.remove_datetime_range(list_index)
    except ItemDoesNotExistException:
        return jsonify({"status": "failed", "message": "Item with that index does not exist"})

    return jsonify({"status": "success"}), 200


if __name__ == '__main__':
    app.run(debug=DEBUG, host='0.0.0.0', port=5000)
