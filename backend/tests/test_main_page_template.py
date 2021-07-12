from django.test import TestCase
from backend.models import User, Article
from django.test import Client
from django.contrib.auth.hashers import make_password


class UserListingTemplateTestCase(TestCase):
    fixtures = ['db.json']
    client = Client()

    def setUp(self):
        User.objects.bulk_create([
            User(
                username=f"admin{i}",
                email=f"admin{i}@mpt.vn",
                password=make_password('123456'),
                is_active=True
            ) for i in range(0, 3)
        ])

    def test_url_reponse(self):
        response = self.client.get('/users')
        self.assertEqual(response.status_code, 200)

    def test_users_listing_template(self):
        response = self.client.get('/users')
        self.assertTemplateUsed(response, 'user_listing.html')

    def test_template_data(self):
        response = self.client.get('/users')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.context['users']), 6)


class ArticleListingTemplateTestCase(TestCase):
    fixtures = ['db.json']
    client = Client()

    def test_url_reponse(self):
        response = self.client.get('/articles')
        self.assertEqual(response.status_code, 200)

    def test_users_listing_template(self):
        response = self.client.get('/articles')
        self.assertTemplateUsed(response, 'articles.html')

    def test_template_data(self):
        response = self.client.get('/articles')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.context['articles']), 100)

    def test_template_data_by_page(self):
        response = self.client.get('/articles?page=2')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.context['articles']), 100)
