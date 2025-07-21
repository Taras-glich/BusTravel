from django.contrib.auth.backends import ModelBackend
from django.db.models import Q
from .models import User  # або from Registration.models import User, залежно від структури

class EmailOrUsernameModelBackend(ModelBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        if username is None:
            username = kwargs.get(User.USERNAME_FIELD)
        try:
            user = User.objects.get(Q(username=username) | Q(email=username))
        except User.DoesNotExist:
            # Щоб не розкривати чи користувача немає, хешуємо пароль "порожнього" юзера для захисту від timing attacks
            User().set_password(password)
        else:
            if user.check_password(password) and self.user_can_authenticate(user):
                return user
        return None
