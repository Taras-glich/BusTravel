from cProfile import Profile

from django.contrib import admin
from .models import User, EmailVerification, Travels

# Register your models here.
admin.site.register(User)
admin.site.register(EmailVerification)
admin.site.register(Travels)


