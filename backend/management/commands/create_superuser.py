from django.core.management.base import BaseCommand
from backend.models import User
from faker import Faker
from dotenv import load_dotenv
import os

load_dotenv(dotenv_path=os.path.join(
    os.path.dirname(__file__), '.env'), verbose=True)

fake = Faker()


class Command(BaseCommand):
    help = "Seed base data"

    def handle(self, *args, **options):
        if not User.objects.filter(username=os.environ.get('SUPERUSER_USERNAME')).exists():
            superuser = User.objects.create_user(
                username=os.environ.get('SUPERUSER_USERNAME'),
                email=os.environ.get('SUPERUSER_EMAIL'),
                is_superuser=True,
                is_staff=True,
            )
            superuser.set_password(os.environ.get('SUPERUSER_PASSWORD'))
            superuser.save()
