from django.contrib import admin
from .models import User
# Register your models here.

admin.site.register(User)


class LogEntryAdmin(admin.ModelAdmin):
    list_display = ('id', 'get_string', 'action_time', 'object_id')
    actions = None

    def get_string(self, obj):
        return str(obj)

    search_fields = ['=user__username', ]
    fieldsets = [
        (None, {'fields': ()}),
    ]

    def __init__(self, *args, **kwargs):
        super(LogEntryAdmin, self).__init__(*args, **kwargs)
        self.list_display_links = None


admin.site.register(admin.models.LogEntry, LogEntryAdmin)
