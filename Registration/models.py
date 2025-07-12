from django.contrib.auth.models import AbstractUser
from django.contrib.auth.hashers import make_password, check_password
from django.db import models
from django.utils.translation import gettext_lazy as _


class User(AbstractUser):
    username = models.CharField(
        max_length=150,
        unique=True,
        verbose_name='Логін'
    )
    email = models.EmailField(
        unique=True,
        verbose_name='Емейл'
    )
    date_joined = models.DateTimeField(
        auto_now_add=True,
        verbose_name='Дата реєстрації'
    )
    is_active = models.BooleanField(
        default=False,
        verbose_name='Активний'
    )

    TYPE_CHOICES = [('user', 'Користувач'), ('carrier', 'Перевізник')]
    type = models.CharField(
        max_length=10,
        choices=TYPE_CHOICES,
        default='user',
        verbose_name='Тип'
    )
    two_factor_auth = models.BooleanField(
        default=False,
        verbose_name='Двоетапна аутентифікація'
    )

    # Відключення полів first_name і last_name, якщо не потрібні
    first_name = None
    last_name = None

    # Fix reverse accessor clashes
    groups = models.ManyToManyField(
        'auth.Group',
        verbose_name='groups',
        blank=True,
        help_text='The groups this user belongs to.',
        related_name="custom_user_groups",  # Custom related_name
        related_query_name="custom_user",
    )
    user_permissions = models.ManyToManyField(
        'auth.Permission',
        verbose_name='user permissions',
        blank=True,
        help_text='Specific permissions for this user.',
        related_name="custom_user_permissions",  # Custom related_name
        related_query_name="custom_user",
    )

    # Add to your User model in models.py
    verification_code = models.CharField(max_length=6, null=True, blank=True)
    verification_code_expires = models.DateTimeField(null=True, blank=True)
    two_factor_code = models.CharField(max_length=6, null=True, blank=True)
    two_factor_code_expires = models.DateTimeField(null=True, blank=True)

    def set_password(self, raw_password):
        self.password = make_password(raw_password)

    def check_password(self, raw_password):
        return check_password(raw_password, self.password)

    def __str__(self):
        return self.username

    LANGUAGE_CHOICES = [
        ('en', 'English'),
        ('uk', 'Українська'),
    ]

    language = models.CharField(
        max_length=2,
        choices=LANGUAGE_CHOICES,
        default='en',
        verbose_name=_('Language')
    )

    class Meta:
        verbose_name = _('User')
        verbose_name_plural = _('Users')


class Travels(models.Model):
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        verbose_name='Власник туру'
    )
    name = models.CharField(
        max_length=100,
        verbose_name='Назва'
    )
    description = models.TextField(
        verbose_name='Опис'
    )
    from_city = models.CharField(
        max_length=100,
        verbose_name='Місто відправлення'
    )
    to_city = models.CharField(
        max_length=100,
        verbose_name='Місто прибуття'
    )
    date_and_time = models.JSONField(
        verbose_name='Дата і час поїздки'
    )
    price = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        verbose_name='Ціна'
    )
    is_active = models.BooleanField(
        default=False,
        verbose_name='Активний'
    )
    created_at = models.DateTimeField(
        auto_now_add=True,
        verbose_name='Дата створення'
    )
    updated_at = models.DateTimeField(
        auto_now=True,
        verbose_name='Дата оновлення'
    )

    class Meta:
        verbose_name = 'Путівка'
        verbose_name_plural = 'Путівки'

    def __str__(self):
        return f"{self.name} ({self.from_city} - {self.to_city})"


class Ticket(models.Model):
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        verbose_name='Користувач'
    )
    travel = models.ForeignKey(
        Travels,
        on_delete=models.CASCADE,
        verbose_name='Путівка'
    )
    place = models.PositiveIntegerField(
        verbose_name='Місце в автобусі'
    )
    created_at = models.DateTimeField(
        auto_now_add=True,
        verbose_name='Дата створення'
    )
    updated_at = models.DateTimeField(
        auto_now=True,
        verbose_name='Дата оновлення'
    )

    class Meta:
        verbose_name = 'Квиток'
        verbose_name_plural = 'Квитки'

    def __str__(self):
        return f"Квиток #{self.id} для {self.user.username} на {self.travel.name}"
