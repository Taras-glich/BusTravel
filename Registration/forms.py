from django import forms
from django.contrib.auth.forms import (
    AuthenticationForm,
    UserCreationForm,
    PasswordChangeForm,
    PasswordResetForm,
    SetPasswordForm
)
from django.core.exceptions import ValidationError
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django.contrib.auth import password_validation
from django_recaptcha.fields import ReCaptchaField
from django_recaptcha.widgets import ReCaptchaV2Checkbox
from .models import User
import unicodedata


class RegisterForm(UserCreationForm):
    """
    Поліпшена форма реєстрації з валідацією, капчею та вибором типу акаунту
    """
    email = forms.EmailField(
        label=_("Email"),
        required=True,
        widget=forms.EmailInput(attrs={
            'class': 'form-control',
            'placeholder': _('your.email@example.com'),
            'autocomplete': 'email'
        })
    )

    type = forms.ChoiceField(
        label=_("Account Type"),
        choices=User.TYPE_CHOICES,
        widget=forms.Select(attrs={'class': 'form-select'})
    )

    captcha = ReCaptchaField(
        widget=ReCaptchaV2Checkbox,
        label="",
        error_messages={'required': _("Please complete the CAPTCHA")}
    )

    class Meta:
        model = User
        fields = ['username', 'email', 'password1', 'password2', 'type', 'captcha']
        widgets = {
            'username': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': _('username'),
                'autocomplete': 'username'
            }),
        }
        help_texts = {
            'username': _('Required. 150 characters or fewer. Letters, digits and @/./+/-/_ only.'),
        }

    def clean_username(self):
        username = self.cleaned_data.get('username')

        # Нормалізація юзернейму (для Unicode)
        username = unicodedata.normalize('NFKC', username)

        if not username.isascii():
            raise ValidationError(_("Username should contain only ASCII characters."))

        if len(username) < 4:
            raise ValidationError(_("Username must be at least 4 characters long."))

        return username

    def clean_email(self):
        email = self.cleaned_data.get('email').strip().lower()

        if User.objects.filter(email=email).exists():
            raise ValidationError(_("This email is already in use. Please use another one."))

        return email

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Кастомізація текстів допомоги для паролів
        self.fields['password1'].widget.attrs.update({
            'class': 'form-control',
            'placeholder': _('Create password')
        })
        self.fields['password2'].widget.attrs.update({
            'class': 'form-control',
            'placeholder': _('Repeat password')
        })


class LoginForm(AuthenticationForm):
    """
    Розширена форма входу з підтримкою email/username та капчею
    """
    username = forms.CharField(
        label=_("Username or Email"),
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': _('username or email'),
            'autocomplete': 'username'
        }),
        strip=True
    )

    password = forms.CharField(
        label=_("Password"),
        strip=False,
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': _('password'),
            'autocomplete': 'current-password'
        }),
    )

    captcha = ReCaptchaField(
        widget=ReCaptchaV2Checkbox,
        label="",
        error_messages={'required': _("Please verify you're not a robot")}
    )

    error_messages = {
        'invalid_login': _(
            "Please enter a correct username/email and password. "
            "Note that both fields may be case-sensitive."
        ),
        'inactive': _("This account is inactive."),
        'rate_limit': _("Too many login attempts. Please try again later."),
    }

    def clean(self):
        username_or_email = self.cleaned_data.get('username')
        password = self.cleaned_data.get('password')

        if username_or_email and password:
            # Пошук користувача по email або username
            user = User.objects.filter(email__iexact=username_or_email).first() or \
                   User.objects.filter(username__iexact=username_or_email).first()

            if user:
                # Перевірка пароля
                if not user.check_password(password):
                    raise ValidationError(
                        self.error_messages['invalid_login'],
                        code='invalid_login',
                    )

                # Перевірка активності акаунту
                self.confirm_login_allowed(user)

                # Якщо все вірно - зберігаємо користувача
                self.user_cache = user
            else:
                raise ValidationError(
                    self.error_messages['invalid_login'],
                    code='invalid_login',
                )

        return self.cleaned_data


class CustomPasswordResetForm(PasswordResetForm):
    """
    Поліпшена форма скидання пароля з додатковою валідацією
    """
    email = forms.EmailField(
        label=_("Email"),
        max_length=254,
        widget=forms.EmailInput(attrs={
            'class': 'form-control',
            'placeholder': _('your.email@example.com'),
            'autocomplete': 'email'
        }),
    )

    def clean_email(self):
        email = self.cleaned_data['email'].strip().lower()
        if not User.objects.filter(email__iexact=email).exists():
            raise ValidationError(_("No account found with this email address."))
        return email


class TwoFactorForm(forms.Form):
    """
    Форма двофакторної аутентифікації з обмеженням спроб
    """
    code = forms.CharField(
        label=_("Verification Code"),
        max_length=6,
        min_length=6,
        required=True,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': '123456',
            'autocomplete': 'off',
            'inputmode': 'numeric'
        }),
        strip=True,
        error_messages={
            'required': _("Please enter the 6-digit code"),
            'min_length': _("Code must be exactly 6 digits"),
            'max_length': _("Code must be exactly 6 digits"),
        }
    )

    def __init__(self, *args, request=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.request = request
        self.user = None

    def clean_code(self):
        code = self.cleaned_data.get('code').strip()
        user_id = self.request.session.get('user_to_authenticate')

        if not user_id:
            raise ValidationError(_("Session expired. Please login again."))

        try:
            self.user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            raise ValidationError(_("User not found."))

        # Перевірка спроб
        if self.user.failed_2fa_attempts >= 3:
            raise ValidationError(_("Too many attempts. Please request a new code."))

        if not self.user.two_factor_code:
            raise ValidationError(_("No active verification code found. Please request a new one."))

        if self.user.two_factor_code != code:
            self.user.failed_2fa_attempts += 1
            self.user.save()
            raise ValidationError(_("Invalid verification code. Attempts left: %d") %
                                  (3 - self.user.failed_2fa_attempts))

        if timezone.now() > self.user.two_factor_code_expires:
            raise ValidationError(_("Verification code has expired. Please request a new one."))

        return code


class CustomPasswordChangeForm(PasswordChangeForm):
    """
    Поліпшена форма зміни пароля з кращим UX
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Оновлюємо атрибути полів
        self.fields['old_password'].widget.attrs.update({
            'class': 'form-control',
            'placeholder': _('Current password')
        })
        self.fields['new_password1'].widget.attrs.update({
            'class': 'form-control',
            'placeholder': _('New password')
        })
        self.fields['new_password2'].widget.attrs.update({
            'class': 'form-control',
            'placeholder': _('Confirm new password')
        })

        # Поліпшений текст допомоги
        self.fields['new_password1'].help_text = password_validation.password_validators_help_text_html()


class AccountDeleteForm(forms.Form):
    """
    Форма видалення акаунту з підтвердженням пароля
    """
    password = forms.CharField(
        label=_("Current Password"),
        strip=False,
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': _('Enter your password to confirm'),
            'autocomplete': 'current-password'
        }),
    )
    confirm = forms.BooleanField(
        label=_("I understand this action cannot be undone"),
        required=True,
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input'})
    )

    def __init__(self, *args, user=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.user = user

    def clean_password(self):
        password = self.cleaned_data.get('password')
        if not self.user.check_password(password):
            raise ValidationError(_("Incorrect password."))
        return password

    def clean_confirm(self):
        confirm = self.cleaned_data.get('confirm')
        if not confirm:
            raise ValidationError(_("You must confirm account deletion."))
        return confirm


class LanguageForm(forms.Form):
    """
    Форма вибору мови інтерфейсу з підтримкою прапорів
    """
    language = forms.ChoiceField(
        label=_("Interface Language"),
        choices=User.LANGUAGE_CHOICES,
        widget=forms.Select(attrs={
            'class': 'form-select',
            'onchange': 'this.form.submit()'
        })
    )


class SetPasswordForm(SetPasswordForm):
    """
    Кастомізована форма встановлення нового пароля
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['new_password1'].widget.attrs.update({
            'class': 'form-control',
            'placeholder': _('New password')
        })
        self.fields['new_password2'].widget.attrs.update({
            'class': 'form-control',
            'placeholder': _('Confirm new password')
        })