from .defaults import *

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql_psycopg2',
        'NAME': 'circle_test',
        'USER': 'root',
        'PASSWORD': '',
        'HOST': '127.0.0.1',
    }
}
