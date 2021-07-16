from django.test import TestCase
from backend.models import User

# Create your tests here.


class UserModelTest(TestCase):

    def test_string_representation(self):
        username = "trungnt"
        email = "trungnt@socicom.vn"
        user = User(username=username, email=email)
        self.assertEqual(str(user), user.username)
