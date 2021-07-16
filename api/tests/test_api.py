from django.test import TestCase, Client
from backend.models import User


class ApiTestCase(TestCase):
    client = Client()

    def setUp(self):
        user = User.objects.create(
            username="admin", email="admin@mpt.vn", is_staff=True, is_superuser=True)
        user.set_password('123456')
        user.save()

    def test_retrieve_access_token(self):
        response = self.client.post(
            '/api/token/',
            {
                'username': 'admin', 'password': '123456'
            },
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 200)
        refresh_token = response.json()['refresh']
        token_response = self.client.post(
            '/api/token/refresh/',
            {
                'refresh': refresh_token
            }
        )
        self.assertEqual(token_response.status_code, 200)
