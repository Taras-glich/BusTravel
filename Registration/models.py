from django.utils import timezone
from datetime import timedelta
from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils.translation import gettext_lazy as _
from django.core.validators import MinLengthValidator, RegexValidator
from django.core.exceptions import ValidationError


class User(AbstractUser):
    """
    Розширена модель користувача з покращеною безпекою та додатковими функціями
    """

    # Валідатори для полів
    username_validator = RegexValidator(
        regex=r'^[\w.@+-]+\Z',
        message=_("Username may contain only letters, numbers and @/./+/-/_ characters.")
    )

    username = models.CharField(
        _('username'),
        max_length=150,
        unique=True,
        help_text=_('Required. 150 characters or fewer. Letters, digits and @/./+/-/_ only.'),
        validators=[username_validator, MinLengthValidator(4)],
        error_messages={
            'unique': _("A user with that username already exists."),
        },
    )

    email = models.EmailField(
        _('email address'),
        unique=True,
        error_messages={
            'unique': _("A user with that email already exists."),
        },
    )

    date_joined = models.DateTimeField(_('date joined'), auto_now_add=True)
    is_active = models.BooleanField(
        _('active'),
        default=False,
        help_text=_('Designates whether this user should be treated as active. '
                    'Unselect this instead of deleting accounts.'),
    )

    # Типи користувачів
    TYPE_CHOICES = [
        ('user', _('Regular User')),
        ('carrier', _('Carrier')),
        ('admin', _('Administrator')),
    ]
    type = models.CharField(
        _('user type'),
        max_length=10,
        choices=TYPE_CHOICES,
        default='user',
    )

    # Налаштування двофакторної аутентифікації
    two_factor_auth = models.BooleanField(
        _('2FA enabled'),
        default=False,
    )
    two_factor_code = models.CharField(
        _('2FA code'),
        max_length=6,
        blank=True,
        null=True,
    )
    two_factor_code_expires = models.DateTimeField(
        _('2FA code expiration'),
        blank=True,
        null=True,
    )
    failed_2fa_attempts = models.PositiveIntegerField(
        _('failed 2FA attempts'),
        default=0,
    )

    # Локалізація
    LANGUAGE_CHOICES = [
        ('en', 'English'),
        ('uk', 'Українська'),
        ('pl', 'Polski'),
    ]
    language = models.CharField(
        _('interface language'),
        max_length=2,
        choices=LANGUAGE_CHOICES,
        default='en',
    )

    # М'яке видалення
    deleted_at = models.DateTimeField(
        _('deletion date'),
        null=True,
        blank=True,
    )
    deletion_reason = models.TextField(
        _('reason for deletion'),
        blank=True,
        null=True,
    )

    # Додаткові поля профілю
    phone_number = models.CharField(
        _('phone number'),
        max_length=20,
        blank=True,
        null=True,
        validators=[RegexValidator(
            regex=r'^\+?[0-9]{9,15}$',
            message=_("Phone number must be entered in the format: '+999999999'. Up to 15 digits allowed.")
        )],
    )
    profile_picture = models.ImageField(
        _('profile picture'),
        upload_to='profile_pics/',
        null=True,
        blank=True,
    )

    # Відключаємо непотрібні поля
    first_name = None
    last_name = None

    class Meta:
        verbose_name = _('user')
        verbose_name_plural = _('users')
        ordering = ['-date_joined']
        indexes = [
            models.Index(fields=['username']),
            models.Index(fields=['email']),
            models.Index(fields=['deleted_at']),
        ]

    def clean(self):
        """Додаткова валідація перед збереженням"""
        super().clean()
        self.email = self.__class__.objects.normalize_email(self.email)

        if self.deleted_at and self.deleted_at < timezone.now():
            raise ValidationError(_('Deletion date cannot be in the past'))

    def is_pending_deletion(self):
        """Чи акаунт запланований на видалення"""
        return self.deleted_at is not None and not self.should_be_deleted()

    def deletion_days_left(self):
        """Кількість днів до видалення акаунту"""
        if not self.is_pending_deletion():
            return None
        return self.deleted_at + timedelta(days=30) - timezone.now()

    def should_be_deleted(self):
        """Чи акаунт має бути видалений"""
        return bool(
            self.deleted_at and
            timezone.now() >= self.deleted_at + timedelta(days=30)
        )

    def restore(self):
        """Відновити акаунт"""
        self.deleted_at = None
        self.deletion_reason = None
        self.is_active = True
        self.save()

    def get_full_name(self):
        """Альтернатива для first_name/last_name"""
        return self.username

    def get_short_name(self):
        """Альтернатива для first_name"""
        return self.username

    def __str__(self):
        return f"{self.username} ({self.get_type_display()})"


class EmailVerification(models.Model):
    """Модель для верифікації email з додатковими перевірками"""

    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='email_verifications',
        verbose_name=_('user'),
    )
    token = models.CharField(
        _('verification token'),
        max_length=128,
        unique=True,
    )
    created_at = models.DateTimeField(
        _('created at'),
        auto_now_add=True,
    )
    expires_at = models.DateTimeField(
        _('expires at'),
    )
    is_used = models.BooleanField(
        _('is used'),
        default=False,
    )
    ip_address = models.GenericIPAddressField(
        _('IP address'),
        blank=True,
        null=True,
    )

    class Meta:
        verbose_name = _('email verification')
        verbose_name_plural = _('email verifications')
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['token']),
            models.Index(fields=['expires_at']),
        ]

    def is_expired(self):
        """Чи токен прострочений"""
        return timezone.now() > self.expires_at

    def is_valid(self):
        """Чи токен дійсний"""
        return not self.is_used and not self.is_expired()

    def mark_used(self):
        """Позначити токен як використаний"""
        self.is_used = True
        self.save()

    def __str__(self):
        return f"Verification for {self.user.email} ({'valid' if self.is_valid() else 'invalid'})"


class Travel(models.Model):
    """Модель подорожі з розширеними полями"""

    TRAVEL_TYPES = [
        ('bus', _('Bus')),
        ('train', _('Train')),
        ('plane', _('Plane')),
    ]

    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='travels',
        verbose_name=_('owner'),
    )
    name = models.CharField(
        _('travel name'),
        max_length=100,
    )
    description = models.TextField(
        _('description'),
        blank=True,
    )
    travel_type = models.CharField(
        _('travel type'),
        max_length=10,
        choices=TRAVEL_TYPES,
        default='bus',
    )
    from_city = models.CharField(
        _('departure city'),
        max_length=100,
    )
    to_city = models.CharField(
        _('arrival city'),
        max_length=100,
    )
    departure_time = models.DateTimeField(
        _('departure time'),
    )
    arrival_time = models.DateTimeField(
        _('arrival time'),
    )
    price = models.DecimalField(
        _('price'),
        max_digits=10,
        decimal_places=2,
    )
    capacity = models.PositiveIntegerField(
        _('capacity'),
        default=50,
    )
    is_active = models.BooleanField(
        _('is active'),
        default=True,
    )
    created_at = models.DateTimeField(
        _('created at'),
        auto_now_add=True,
    )
    updated_at = models.DateTimeField(
        _('updated at'),
        auto_now=True,
    )

    class Meta:
        verbose_name = _('travel')
        verbose_name_plural = _('travels')
        ordering = ['-departure_time']
        indexes = [
            models.Index(fields=['from_city', 'to_city']),
            models.Index(fields=['departure_time']),
        ]

    def clean(self):
        """Валідація дат подорожі"""
        if self.arrival_time <= self.departure_time:
            raise ValidationError(_('Arrival time must be after departure time'))

    def duration(self):
        """Тривалість подорожі"""
        return self.arrival_time - self.departure_time

    def available_seats(self):
        """Кількість вільних місць"""
        return self.capacity - self.tickets.count()

    def __str__(self):
        return f"{self.get_travel_type_display()} from {self.from_city} to {self.to_city} at {self.departure_time}"


class Ticket(models.Model):
    """Модель квитка з додатковими перевірками"""

    TICKET_STATUSES = [
        ('reserved', _('Reserved')),
        ('paid', _('Paid')),
        ('cancelled', _('Cancelled')),
    ]

    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='tickets',
        verbose_name=_('user'),
    )
    travel = models.ForeignKey(
        Travel,
        on_delete=models.CASCADE,
        related_name='tickets',
        verbose_name=_('travel'),
    )
    seat_number = models.PositiveIntegerField(
        _('seat number'),
        null=True,
        blank=True,
    )
    status = models.CharField(
        _('status'),
        max_length=10,
        choices=TICKET_STATUSES,
        default='reserved',
    )
    price_paid = models.DecimalField(
        _('price paid'),
        max_digits=10,
        decimal_places=2,
        default=0.0
    )

    # Виправлення: зробимо поле nullable тимчасово
    booking_reference = models.CharField(
        _('booking reference'),
        max_length=12,
        unique=True,
        null=True,
        blank=True,
    )

    created_at = models.DateTimeField(
        _('created at'),
        auto_now_add=True,
    )
    updated_at = models.DateTimeField(
        _('updated at'),
        auto_now=True,
    )

    class Meta:
        verbose_name = _('ticket')
        verbose_name_plural = _('tickets')
        ordering = ['-created_at']
        constraints = [
            models.UniqueConstraint(
                fields=['travel', 'seat_number'],
                name='unique_seat_per_travel',
                condition=models.Q(status__in=['reserved', 'paid']),
            ),
        ]

    def clean(self):
        """Додаткова валідація квитка"""
        if self.seat_number > self.travel.capacity:
            raise ValidationError(_('Seat number exceeds travel capacity'))

        if self.price_paid > self.travel.price * 1.5:
            raise ValidationError(_('Price paid is too high'))

    def __str__(self):
        return f"Ticket #{self.booking_reference or 'N/A'} for {self.user.username} ({self.get_status_display()})"
