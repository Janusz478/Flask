import os

SECRET_KEY = os.urandom(20)
JWT_SECRET_KEY = os.urandom(20)
JWT_TOKEN_LOCATION = "cookies"
JWT_COOKIE_SECURE = True
JWT_COOKIE_CSRF_PROTECT = True
