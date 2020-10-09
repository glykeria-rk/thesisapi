import typing
import datetime


from dateutil.rrule import rrulestr
from flask import jsonify


def validate_rrule_str(rrule_str: str) -> typing.Tuple[bool, typing.Dict]:
    try:
        rrule = rrulestr(rrule_str)
    except ValueError:
        return False, jsonify({"status": "failed", "message": "Invalid RRule string"})
    except TypeError:
        return False, jsonify({"status": "failed", "message": "RRule is not a string"})
    return True, None

def validate_and_get_dt_str(dt_str: str, variable_name: str) -> typing.Tuple[bool, typing.Dict, str]:
    """
    Returns
    -------
    Tuple[success, message, parsed_value]
    """
    try:
        dt = datetime.datetime.fromtimestamp(dt_str)
    except TypeError:
        return False, jsonify({"status": "failed", "message": "{variable_name} should be an integer".format(variable_name=variable_name)}), None
    return True, None, dt