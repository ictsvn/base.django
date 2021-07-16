from django.test import TestCase
from backend.models import User
from django.contrib.admin.sites import AdminSite
from django.contrib.admin.models import LogEntry
from backend.admin import LogEntryAdmin

# Create your tests here.


class LogEntryModelAdminTest(TestCase):

    def setUp(self):
        user = User.objects.create(username="admin", email="admin@mpt.vn", is_staff=True, is_superuser=True)
        self.log_entry = LogEntry.objects.create(
            user=user,
            action_flag=2
        )
        self.site = AdminSite()
        return None

    def test_modeladmin_str(self):
        ma = LogEntryAdmin(LogEntry, self.log_entry)
        self.assertEqual(str(ma), 'admin.LogEntryAdmin')

    def test_get_string(self):
        ma = LogEntryAdmin(LogEntry, self.log_entry)
        self.assertEqual(ma.get_string('Changed "admin" - Changed password.'), 'Changed "admin" - Changed password.')
