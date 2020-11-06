import jwt
from dashboard.settings import JWT_TOKEN
from django.core.validators import validate_email
from django.core.exceptions import ValidationError


def authenticate_user(token):
    try:
        token_value = jwt.decode(token[7:].encode('utf-8'), algorithm='HS256', key=JWT_TOKEN)
        print(token_value)
        return token_value
    except:
        return {'error': "Invalid token"}


def validate_user_email(email):
    try:
        validate_email(email)
        return True
    except ValidationError:
        return False