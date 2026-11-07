import os

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'appdb',
        'USER': 'app',
        'PASSWORD': os.environ['DB_PASSWORD'],
        'HOST': 'db',
    },
    'replica': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': 'replica.sqlite3',
        'PASSWORD': '',
    },
}
