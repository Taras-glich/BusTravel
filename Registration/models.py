from django.utils import timezone
from datetime import timedelta
from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils.translation import gettext_lazy as _


class User(AbstractUser):
    """
    Користувацька модель з:
    - двоетапною аутентифікацією
    - soft delete
    - локалізацією інтерфейсу
    - поділом на типи (user/carrier)
    """

    username = models.CharField(
        max_length=150,
        unique=True,
        verbose_name=_('Логін'),
        help_text=_('Required. 150 characters or fewer. Letters, digits and @/./+/-/_ only.')
    )
    email = models.EmailField(
        unique=True,
        verbose_name=_('Емейл'),
        help_text=_('Required. Enter a valid email address.')
    )
    date_joined = models.DateTimeField(auto_now_add=True, verbose_name=_('Дата реєстрації'))
    is_active = models.BooleanField(default=False, verbose_name=_('Активний'))

    TYPE_CHOICES = [
        ('user', _('Користувач')),
        ('carrier', _('Перевізник'))
    ]
    type = models.CharField(
        max_length=10,
        choices=TYPE_CHOICES,
        default='user',
        verbose_name=_('Тип')
    )

    two_factor_auth = models.BooleanField(default=False, verbose_name=_('Двоетапна аутентифікація'))
    two_factor_code = models.CharField(max_length=6, blank=True, null=True, verbose_name=_('2FA код'))
    two_factor_code_expires = models.DateTimeField(blank=True, null=True, verbose_name=_('Час закінчення дії 2FA'))

    # Локалізація
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

    deleted_at = models.DateTimeField(null=True, blank=True, verbose_name=_('Дата запланованого видалення'))

    # Відключаємо непотрібні поля AbstractUser
    first_name = None
    last_name = None

    # Groups / permissions з унікальними related_name
    groups = models.ManyToManyField(
        'auth.Group',
        verbose_name=_('Groups'),
        blank=True,
        related_name="custom_user_groups",
        related_query_name="custom_user",
        help_text=_('The groups this user belongs to.')
    )
    user_permissions = models.ManyToManyField(
        'auth.Permission',
        verbose_name=_('User permissions'),
        blank=True,
        related_name="custom_user_permissions",
        related_query_name="custom_user",
        help_text=_('Specific permissions for this user.')
    )

    def is_pending_deletion(self):
        """Чи акаунт запланований на видалення і ще не видалений."""
        return self.deleted_at is not None and timezone.now() < self.deleted_at + timedelta(days=30)

    def deletion_days_left(self):
        """Скільки днів залишилося до остаточного видалення."""
        if not self.is_pending_deletion():
            return None
        delta = (self.deleted_at + timedelta(days=30)) - timezone.now()
        return max(delta.days, 0)

    def should_be_deleted(self):
        """Чи акаунт прострочений для видалення (для cron чи celery tasks)."""
        return self.deleted_at and timezone.now() >= self.deleted_at + timedelta(days=30)

    def restore(self):
        """Скасувати видалення акаунту."""
        self.deleted_at = None
        self.is_active = True
        self.save()

    def permanent_delete(self):
        """Остаточне видалення акаунту."""
        super().delete()

    def __str__(self):
        return self.username

    class Meta:
        verbose_name = _('User')
        verbose_name_plural = _('Users')
        ordering = ['username']


class EmailVerification(models.Model):
    """
    Токени підтвердження email з часом дії.
    """
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='email_verifications',
        verbose_name=_('Користувач')
    )
    token = models.CharField(max_length=128, unique=True, verbose_name=_('Токен підтвердження'))
    created_at = models.DateTimeField(auto_now_add=True, verbose_name=_('Дата створення'))
    expires_at = models.DateTimeField(verbose_name=_('Дата закінчення дії токена'), db_index=True)
    is_used = models.BooleanField(default=False, verbose_name=_('Використаний'))

    def is_expired(self):
        return timezone.now() > self.expires_at

    def mark_used(self):
        self.is_used = True
        self.save()

    def __str__(self):
        return f"{self.user.email} - Used: {self.is_used}"

    class Meta:
        verbose_name = _('Підтвердження email')
        verbose_name_plural = _('Підтвердження email')
        ordering = ['-created_at']


class Travels(models.Model):
    """
    Путівки (подорожі) з містами, ціною та датами.
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE, verbose_name=_('Власник туру'))
    name = models.CharField(max_length=100, verbose_name=_('Назва'))
    description = models.TextField(verbose_name=_('Опис'))
    from_city = models.CharField(max_length=100, verbose_name=_('Місто відправлення'))
    to_city = models.CharField(max_length=100, verbose_name=_('Місто прибуття'))
    date_and_time = models.JSONField(
        verbose_name=_('Дата і час поїздки'),
        help_text=_('Format example: {"2025-07-25": ["09:00", "14:00"]}')
    )
    price = models.DecimalField(max_digits=10, decimal_places=2, verbose_name=_('Ціна'))
    is_active = models.BooleanField(default=False, verbose_name=_('Активний'))
    created_at = models.DateTimeField(auto_now_add=True, verbose_name=_('Дата створення'))
    updated_at = models.DateTimeField(auto_now=True, verbose_name=_('Дата оновлення'))

    def __str__(self):
        return f"{self.name} ({self.from_city} → {self.to_city})"

    class Meta:
        verbose_name = _('Путівка')
        verbose_name_plural = _('Путівки')
        ordering = ['-created_at']


class Ticket(models.Model):
    """
    Квитки на путівки з місцем у автобусі.
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE, verbose_name=_('Користувач'))
    travel = models.ForeignKey(Travels, on_delete=models.CASCADE, verbose_name=_('Путівка'))
    place = models.PositiveIntegerField(verbose_name=_('Місце в автобусі'))
    created_at = models.DateTimeField(auto_now_add=True, verbose_name=_('Дата створення'))
    updated_at = models.DateTimeField(auto_now=True, verbose_name=_('Дата оновлення'))

    def __str__(self):
        return f"Квиток #{self.id} для {self.user.username} на {self.travel.name}"

    class Meta:
        verbose_name = _('Квиток')
        verbose_name_plural = _('Квитки')
        ordering = ['-created_at']
        constraints = [
            models.UniqueConstraint(
                fields=['travel', 'place'],
                name='unique_travel_place'
            )
        ]
