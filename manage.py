#!/usr/bin/env python
import os
import sys
import time
import psycopg2
from dotenv import load_dotenv

load_dotenv(dotenv_path=os.path.join(
    os.path.dirname(__file__), '.env'), verbose=True)

if __name__ == "__main__":

    if sys.argv[1:2] == ['runserver']:
        while True:
            try:
                connection = psycopg2.connect(
                    dbname=os.environ.get('POSTGRES_DB'),
                    user=os.environ.get('POSTGRES_USER'),
                    password=os.environ.get('POSTGRES_PASSWORD'),
                    host=os.environ.get('POSTGRES_HOST'),
                    port=os.environ.get('POSTGRES_EXPOSE_PORT')
                )

                if connection.closed == 0:
                    break
                time.sleep(1)
            except:
                time.sleep(1)
                print("DB is not yet ready. Retry")
                pass

    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "base.settings")
    try:
        from django.core.management import execute_from_command_line
    except ImportError:
        # The above import may fail for some other reason. Ensure that the
        # issue is really that Django is missing to avoid masking other
        # exceptions on Python 2.
        try:
            import django
        except ImportError:
            raise ImportError(
                "Couldn't import Django. Are you sure it's installed and "
                "available on your PYTHONPATH environment variable? Did you "
                "forget to activate a virtual environment?"
            )
        raise
    execute_from_command_line(sys.argv)
