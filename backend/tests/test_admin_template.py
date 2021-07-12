import os
from django.test import TestCase
from backend.models import User
from django.test import Client


class AdminTemplateTestCase(TestCase):
    client = Client()

    def setUp(self):
        user = User.objects.create(
            username="admin", email="admin@mpt.vn", is_staff=True, is_superuser=True)
        user.set_password('123456')
        user.save()

    def test_login_fail(self):
        self.client.login(username='admin', password='1234562')
        self.assertEqual(self.client.get('/admin/').status_code, 302)

    def test_login_success(self):
        self.client.login(username='admin', password='123456')
        self.assertEqual(self.client.get('/admin/').status_code, 200)

    def test_admin_header(self):
        self.client.login(username='admin', password='123456')
        res = self.client.get('/admin/')
        self.assertContains(res, os.environ.get(
            'ADMIN_SITE_HEADER') or 'Django administration', status_code=200)
