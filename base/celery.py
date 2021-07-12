from __future__ import absolute_import, unicode_literals
import os
from celery import Celery
from celery.schedules import crontab
from dotenv import load_dotenv

# set the default Django settings module for the 'celery' program.
load_dotenv(os.path.join(os.path.dirname(os.path.dirname(__file__)), '.env'))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'base.settings')

app = Celery('base')

# Using a string here means the worker don't have to serialize
# the configuration object to child processes.
# - namespace='CELERY' means all celery-related configuration keys
#   should have a `CELERY_` prefix.
app.config_from_object('django.conf:settings', namespace='CELERY')

# Load task modules from all registered Django app configs.
app.autodiscover_tasks()


@app.on_after_configure.connect
def setup_periodic_tasks(sender, **kwargs):
    # Calls test('world') every 30 seconds
    # sender.add_periodic_task(1.0, test.s('Test beat and Celery'))
    # sender.add_periodic_task(10.0, test.s('Hello World'))
    print("setup_periodic_tasks")


# @app.task(bind=True)
# def debug_task(self):
#     print('Request: {0!r}'.format(self.request))


@app.task
def test(str):
    print("Testing task: " + str)
    return str
