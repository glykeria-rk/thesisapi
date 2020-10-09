from flask_jwt_extended import verify_fresh_jwt_in_request
from flask_jwt_extended import verify_jwt_in_request
from flask_jwt_extended import get_jwt_claims 
from flask_jwt_extended import get_jwt_identity
from functools import wraps

def admin_required(fn):
    """
    Checks whether JWT claim
    is_admin == True. If not,
    returns a 403. Otherwise
    continue wrapped function
    and inject username as 
    keyword argument.
    """
    @wraps(fn)
    def wrapper(*args, **kwargs):
        verify_jwt_in_request()
        claims = get_jwt_claims()
        if claims['roles'] != 'admin':
            return jsonify(msg='Admins only!'), 403
        else:
            identity = get_jwt_identity()
            kwargs['email_address'] = identity
            return fn(*args, **kwargs)
    return wrapper


def user_required(fn):
    """
    Checks whether a valid JWT
    token has been supplied and
    injects username as keyword
    argument.
    """
    @wraps(fn)
    def wrapper(*args, **kwargs):
        verify_jwt_in_request()
        identity = get_jwt_identity()
        kwargs['username'] = identity
        return fn(*args, **kwargs)
    return wrapper


def pi_required(fn):
    """
    Checks whether it's the 
    Raspberry Pi.
    To implement
    """
    pass
