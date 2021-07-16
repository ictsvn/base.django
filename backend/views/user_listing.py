from django.shortcuts import render
from backend.models import User
# Create your views here.


def user_listing(request):
    users = User.objects.all()
    return render(request, 'user_listing.html', {'users': users})
