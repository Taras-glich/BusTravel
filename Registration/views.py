from django.shortcuts import render, redirect
from django.contrib.auth import login, logout, authenticate, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.core.mail import send_mail
from django.conf import settings
from django.contrib import messages
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django.http import HttpResponseRedirect
from django.utils.translation.trans_real import activate

from .forms import (
    RegisterForm, LoginForm, TwoFactorForm,
    CustomPasswordChangeForm, AccountDeleteForm, LanguageForm
)
from .models import User
import random
import string
from datetime import timedelta


def home(request):
    return render(request, 'registration/index.html')


def register_view(request):
    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.is_active = False  # User needs to verify email first
            user.save()

            # Generate and save verification code
            verification_code = ''.join(random.choices(string.digits, k=6))
            user.verification_code = verification_code
            user.verification_code_expires = timezone.now() + timedelta(minutes=10)
            user.save()

            # Send verification email
            send_mail(
                _('Verify your email'),
                _('Your verification code is: %(code)s') % {'code': verification_code},
                settings.EMAIL_HOST_USER,
                [user.email],
                fail_silently=False,
            )

            request.session['user_to_verify'] = user.id
            return redirect('verify_email')
    else:
        form = RegisterForm()
    return render(request, 'registration/register.html', {'form': form})


def verify_email_view(request):
    user_id = request.session.get('user_to_verify')
    if not user_id:
        messages.error(request, _('Verification session expired'))
        return redirect('register')

    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        messages.error(request, _('User not found'))
        return redirect('register')

    if request.method == 'POST':
        code = request.POST.get('code', '').strip()
        if not code:
            messages.error(request, _('Please enter verification code'))
        elif code == user.verification_code:
            if timezone.now() <= user.verification_code_expires:
                user.is_active = True
                user.verification_code = None
                user.verification_code_expires = None
                user.save()
                del request.session['user_to_verify']
                messages.success(request, _('Email verified successfully! You can now login.'))
                return redirect('login')
            else:
                messages.error(request, _('Verification code has expired.'))
        else:
            messages.error(request, _('Invalid verification code.'))

    return render(request, 'registration/verify_email.html')


def login_view(request):
    if request.user.is_authenticated:
        return redirect('profile')

    if request.method == 'POST':
        form = LoginForm(request, data=request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            user = authenticate(request, username=username, password=password)

            if user is not None:
                if user.two_factor_auth:
                    # Generate 2FA code
                    code = ''.join(random.choices(string.digits, k=settings.TWO_FACTOR_CODE_LENGTH))
                    user.two_factor_code = code
                    user.two_factor_code_expires = timezone.now() + timedelta(
                        seconds=settings.TWO_FACTOR_CODE_VALIDITY
                    )
                    user.save()

                    # Send 2FA code via email
                    send_mail(
                        _('Your Two-Factor Authentication Code'),
                        _('Your verification code is: %(code)s') % {'code': code},
                        settings.EMAIL_HOST_USER,
                        [user.email],
                        fail_silently=False,
                    )

                    request.session['user_to_authenticate'] = user.id
                    request.session.modified = True
                    return redirect('two_factor_verify')
                else:
                    login(request, user)
                    messages.success(request, _('Welcome back, %(username)s!') % {'username': user.username})
                    return redirect('profile')
        messages.error(request, _('Invalid username or password.'))
    else:
        form = LoginForm()
    return render(request, 'registration/login.html', {'form': form})


def two_factor_verify_view(request):
    if request.user.is_authenticated:
        return redirect('profile')

    user_id = request.session.get('user_to_authenticate')
    if not user_id:
        messages.error(request, _('Session expired, please login again'))
        return redirect('login')

    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        messages.error(request, _('User not found'))
        return redirect('login')

    if request.method == 'POST':
        form = TwoFactorForm(request.POST, request=request)
        if form.is_valid():
            # Clear the 2FA code after successful verification
            user.two_factor_code = None
            user.two_factor_code_expires = None
            user.save()

            del request.session['user_to_authenticate']
            login(request, user)
            messages.success(request, _('Welcome back, %(username)s!') % {'username': user.username})
            return redirect('profile')
    else:
        form = TwoFactorForm(request=request)

    return render(request, 'registration/two_factor_verify.html', {
        'form': form,
        'email': user.email
    })


@login_required
def logout_view(request):
    logout(request)
    messages.success(request, _('You have been logged out successfully.'))
    return redirect('home')


@login_required
def profile_view(request):
    language_form = LanguageForm(initial={'language': request.user.language})
    return render(request, 'registration/profile.html', {
        'user': request.user,
        'language_form': language_form
    })


@login_required
def toggle_two_factor(request):
    user = request.user
    user.two_factor_auth = not user.two_factor_auth
    user.save()
    status = _("enabled") if user.two_factor_auth else _("disabled")
    messages.success(request, _('Two-factor authentication has been %(status)s.') % {'status': status})
    return redirect('profile')


@login_required
def change_language(request):
    if request.method == 'POST':
        form = LanguageForm(request.POST)
        if form.is_valid():
            language = form.cleaned_data['language']
            request.user.language = language
            request.user.save()
            activate(language)
            response = HttpResponseRedirect(request.META.get('HTTP_REFERER', '/'))
            response.set_cookie('django_language', language)
            return response
    return redirect('profile')


@login_required
def change_password(request):
    if request.method == 'POST':
        form = CustomPasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            user = form.save()
            update_session_auth_hash(request, user)
            messages.success(request, _('Your password was successfully updated!'))
            return redirect('profile')
    else:
        form = CustomPasswordChangeForm(request.user)
    return render(request, 'registration/change_password.html', {'form': form})


@login_required
def delete_account(request):
    if request.method == 'POST':
        form = AccountDeleteForm(request.POST)
        if form.is_valid():
            password = form.cleaned_data['password']
            user = authenticate(username=request.user.username, password=password)
            if user is not None:
                user.delete()
                messages.success(request, _('Your account has been deleted successfully.'))
                return redirect('home')
            messages.error(request, _('Incorrect password.'))
    else:
        form = AccountDeleteForm()
    return render(request, 'registration/delete_account.html', {'form': form})