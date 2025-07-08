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


class RegisterForm(UserCreationForm):
    email = forms.EmailField(
        label=_("Email"),
        required=True,
        widget=forms.EmailInput(attrs={'autocomplete': 'email'})
    )
    type = forms.ChoiceField(
        label=_("Account Type"),
        choices=User.TYPE_CHOICES,
        widget=forms.Select()
    )

    class Meta:
        model = User
        fields = ['username', 'email', 'password1', 'password2', 'type']
        labels = {
            'username': _('Username'),
        }

    def clean_email(self):
        email = self.cleaned_data.get('email')
        if User.objects.filter(email=email).exists():
            raise ValidationError(_("This email is already in use."))
        return email


class LoginForm(AuthenticationForm):
    username = forms.CharField(
        label=_("Username or Email"),
        widget=forms.TextInput(attrs={'autocomplete': 'username'})
    )
    error_messages = {
        'invalid_login': _(
            "Please enter a correct username/email and password."
        ),
        'inactive': _("This account is inactive."),
    }


class TwoFactorForm(forms.Form):
    code = forms.CharField(
        label=_("Verification Code"),
        max_length=6,
        min_length=6,
        required=True,
        widget=forms.TextInput(attrs={
            'placeholder': '000000',
            'autocomplete': 'off'
        })
    )

    def __init__(self, *args, **kwargs):
        self.request = kwargs.pop('request', None)
        super().__init__(*args, **kwargs)

    def clean_code(self):
        code = self.cleaned_data.get('code', '').strip()
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
    language = forms.ChoiceField(
        label=_("Interface Language"),
        choices=User.LANGUAGE_CHOICES,
        widget=forms.Select(attrs={
            'onchange': 'this.form.submit()',
            'class': 'language-selector'
        })
    )