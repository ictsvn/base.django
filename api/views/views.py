from rest_framework import serializers, viewsets
from django.contrib import admin
from backend.models import User


class LogEntrySerializer(serializers.ModelSerializer):
    class Meta:
        model = admin.models.LogEntry
        fields = (
            '__all__')


class LogEntryViewSet(viewsets.ModelViewSet):
    queryset = admin.models.LogEntry.objects.all()
    serializer_class = LogEntrySerializer


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        exclude = (
            'password',)


# abc
class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer
