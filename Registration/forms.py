from django import forms
from django.contrib.auth.forms import (
    AuthenticationForm,
    UserCreationForm,
    PasswordChangeForm
)
from django.core.exceptions import ValidationError
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django.contrib.auth import password_validation
from .models import User
from django_recaptcha.fields import ReCaptchaField
from django_recaptcha.widgets import ReCaptchaV2Checkbox


class RegisterForm(UserCreationForm):
    """
    Форма реєстрації користувача з Captcha та вибором типу акаунту.
    """
    email = forms.EmailField(
        label=_("Email"),
        required=True,
        widget=forms.EmailInput(attrs={'autocomplete': 'email', 'placeholder': _('Enter your email')})
    )
    type = forms.ChoiceField(
        label=_("Account Type"),
        choices=User.TYPE_CHOICES,
        widget=forms.Select()
    )
    captcha = ReCaptchaField(widget=ReCaptchaV2Checkbox, label=_("Підтвердіть, що ви не робот"))

    class Meta:
        model = User
        fields = ['username', 'email', 'password1', 'password2', 'type', 'captcha']
        labels = {
            'username': _('Username'),
        }
        widgets = {
            'username': forms.TextInput(attrs={'placeholder': _('Enter your username')}),
        }

    def clean_email(self):
        """
        Перевірка унікальності email.
        """
        email = self.cleaned_data.get('email').strip().lower()
        if User.objects.filter(email=email).exists():
            raise ValidationError(_("This email is already in use."))
        return email


class LoginForm(AuthenticationForm):
    """
    Форма входу з Captcha.
    """
    username = forms.CharField(
        label=_("Username or Email"),
        widget=forms.TextInput(attrs={'autocomplete': 'username', 'placeholder': _('Enter username or email')}),
        strip=True
    )
    captcha = ReCaptchaField(widget=ReCaptchaV2Checkbox, label=_("Підтвердіть, що ви не робот"))

    error_messages = {
        'invalid_login': _("Please enter a correct username/email and password."),
        'inactive': _("This account is inactive."),
    }


class TwoFactorForm(forms.Form):
    """
    Форма для вводу 2FA коду.
    """
    code = forms.CharField(
        label=_("Verification Code"),
        max_length=6,
        min_length=6,
        required=True,
        widget=forms.TextInput(attrs={
            'placeholder': '000000',
            'autocomplete': 'off'
        }),
        strip=True
    )

    def __init__(self, *args, request=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.request = request

    def clean_code(self):
        """
        Перевірка правильності та дії 2FA коду.
        """
        code = self.cleaned_data.get('code')
        user_id = self.request.session.get('user_to_authenticate')

        if not user_id:
            raise ValidationError(_("Session expired. Please login again."))

        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            raise ValidationError(_("User not found."))

        if not user.two_factor_code:
            raise ValidationError(_("No active verification code found."))

        if user.two_factor_code != code:
            raise ValidationError(_("Invalid verification code."))

        if timezone.now() > user.two_factor_code_expires:
            raise ValidationError(_("Verification code has expired."))

        return code


class CustomPasswordChangeForm(PasswordChangeForm):
    """
    Форма зміни пароля користувача.
    """
    old_password = forms.CharField(
        label=_("Current Password"),
        strip=False,
        widget=forms.PasswordInput(attrs={
            'autocomplete': 'current-password',
            'placeholder': _('Enter current password')
        }),
    )
    new_password1 = forms.CharField(
        label=_("New Password"),
        widget=forms.PasswordInput(attrs={
            'autocomplete': 'new-password',
            'placeholder': _('Enter new password')
        }),
        strip=False,
        help_text=password_validation.password_validators_help_text_html(),
    )
    new_password2 = forms.CharField(
        label=_("Confirm New Password"),
        strip=False,
        widget=forms.PasswordInput(attrs={
            'autocomplete': 'new-password',
            'placeholder': _('Repeat new password')
        }),
    )


class AccountDeleteForm(forms.Form):
    """
    Форма підтвердження видалення акаунту.
    """
    password = forms.CharField(
        label=_("Confirm Password"),
        strip=False,
        widget=forms.PasswordInput(attrs={
            'autocomplete': 'current-password',
            'placeholder': _('Enter your password to confirm')
        }),
        help_text=_("Enter your password to confirm account deletion.")
    )


class LanguageForm(forms.Form):
    """
    Форма вибору мови інтерфейсу.
    """
    language = forms.ChoiceField(
        label=_("Interface Language"),
        choices=User.LANGUAGE_CHOICES,
        widget=forms.Select(attrs={
            'onchange': 'this.form.submit()',
            'class': 'language-selector'
        })
    )
