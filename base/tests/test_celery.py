from django.test import TestCase
from base.celery import test

# Create your tests here.


class CeleryTest(TestCase):

    def test_test(self):
        str = 'hello123'
        result = test(str=str)
        self.assertEqual(result, str)
