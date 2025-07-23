import secrets
import random
import string
from datetime import timedelta
from .tasks import send_email_task
from django.shortcuts import render, redirect
from django.contrib.auth import login, logout, authenticate, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.core.mail import send_mail
from django.conf import settings
from django.contrib import messages
from django.urls import reverse
from django.utils import timezone
from django.utils.http import urlencode
from django.utils.translation import gettext_lazy as _
from django.http import HttpResponseRedirect
from django.utils.translation.trans_real import activate
from django.views.decorators.csrf import csrf_protect

from .forms import (
    RegisterForm, LoginForm, TwoFactorForm,
    CustomPasswordChangeForm, AccountDeleteForm, LanguageForm
)
from .models import User, EmailVerification


def home(request):
    """Головна сторінка."""
    return render(request, 'registration/index.html')


@login_required
def profile_view(request):
    """Сторінка профілю користувача з інформацією про стан видалення."""
    language_form = LanguageForm(initial={'language': request.user.language})
    pending_deletion = request.user.is_pending_deletion()
    days_left = None
    if pending_deletion:
        delta = request.user.deleted_at + timedelta(days=30) - timezone.now()
        days_left = max(delta.days, 0)

    return render(request, 'registration/profile.html', {
        'user': request.user,
        'language_form': language_form,
        'pending_deletion': pending_deletion,
        'days_left': days_left,
    })


@csrf_protect
def register_view(request):
    """Реєстрація нового користувача з email-підтвердженням через Celery."""
    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.is_active = False
            user.save()

            token = secrets.token_urlsafe(32)
            expires_at = timezone.now() + timedelta(hours=24)

            EmailVerification.objects.create(
                user=user,
                token=token,
                expires_at=expires_at
            )

            verify_url = request.build_absolute_uri(
                reverse('verify_email_link') + '?' + urlencode({'token': token})
            )

            subject = _('Підтвердіть ваш email')
            message = _('Перейдіть за посиланням для підтвердження: %(url)s') % {'url': verify_url}
            send_email_task.delay(subject, message, [user.email])

            messages.success(request, _('На вашу пошту надіслано лист для підтвердження.'))
            return redirect('login')
    else:
        form = RegisterForm()
    return render(request, 'registration/register.html', {'form': form})


def verify_email_link_view(request):
    """Перевірка email-посилання."""
    token = request.GET.get('token')
    if not token:
        messages.error(request, _('Неправильне посилання для підтвердження.'))
        return redirect('register')

    try:
        verification = EmailVerification.objects.get(token=token, is_used=False)
    except EmailVerification.DoesNotExist:
        messages.error(request, _('Неправильний або використаний токен підтвердження.'))
        return redirect('register')

    if verification.is_expired():
        messages.error(request, _('Термін дії посилання для підтвердження минув.'))
        return redirect('register')

    user = verification.user
    user.is_active = True
    user.save()

    verification.mark_used()

    messages.success(request, _('Ваш email підтверджено! Тепер ви можете увійти.'))
    return redirect('login')


@csrf_protect
def login_view(request):
    """Вхід користувача з 2FA через Celery."""
    if request.user.is_authenticated:
        return redirect('profile')

    if request.method == 'POST':
        form = LoginForm(request, data=request.POST)
        if form.is_valid():
            user = form.get_user()
            if user:
                if user.is_pending_deletion():
                    messages.warning(request, _('Ваш акаунт заплановано на видалення. Ви можете його відновити у профілі.'))
                if user.two_factor_auth:
                    code = ''.join(random.choices(string.digits, k=settings.TWO_FACTOR_CODE_LENGTH))
                    user.two_factor_code = code
                    user.two_factor_code_expires = timezone.now() + timedelta(seconds=settings.TWO_FACTOR_CODE_VALIDITY)
                    user.save()

                    subject = _('Your Two-Factor Authentication Code')
                    message = _('Your verification code is: %(code)s') % {'code': code}
                    send_email_task.delay(subject, message, [user.email])

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


@csrf_protect
def two_factor_verify_view(request):
    """Перевірка двофакторного коду."""
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
    """Вихід з акаунту."""
    logout(request)
    messages.success(request, _('You have been logged out successfully.'))
    return redirect('home')


@login_required
def toggle_two_factor(request):
    """Увімкнення або вимкнення двофакторної автентифікації."""
    user = request.user
    user.two_factor_auth = not user.two_factor_auth
    user.save()
    status = _("enabled") if user.two_factor_auth else _("disabled")
    messages.success(request, _('Two-factor authentication has been %(status)s.') % {'status': status})
    return redirect('profile')


@login_required
@csrf_protect
def change_language(request):
    """Зміна мови інтерфейсу."""
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
@csrf_protect
def change_password(request):
    """Зміна пароля користувача."""
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
@csrf_protect
def delete_account(request):
    """Запланувати видалення акаунту через 30 днів (soft delete) з повідомленням через Celery."""
    if request.method == 'POST':
        form = AccountDeleteForm(request.POST)
        if form.is_valid():
            password = form.cleaned_data['password']
            user = authenticate(username=request.user.username, password=password)
            if user is not None:
                user.deleted_at = timezone.now()
                user.save()

                subject = _('Account Deletion Scheduled')
                message = _('Your account is scheduled for deletion in 30 days. You can restore it anytime before then.')
                send_email_task.delay(subject, message, [user.email])

                messages.success(request, _('Your account is scheduled for deletion in 30 days. You can restore it anytime before then.'))
                return redirect('profile')
            messages.error(request, _('Incorrect password.'))
    else:
        form = AccountDeleteForm()
    return render(request, 'registration/delete_account.html', {'form': form})



@login_required
@csrf_protect
def permanent_delete_account_view(request):
    """Повне видалення акаунту з БД."""
    if request.method == 'POST':
        form = AccountDeleteForm(request.POST)
        if form.is_valid():
            password = form.cleaned_data['password']
            user = authenticate(username=request.user.username, password=password)
            if user is not None:
                user.permanent_delete()
                logout(request)
                messages.success(request, _('Your account has been permanently deleted.'))
                return redirect('home')
            messages.error(request, _('Incorrect password.'))
    else:
        form = AccountDeleteForm()
    return render(request, 'registration/permanent_delete_account.html', {'form': form})

@login_required
def cancel_account_deletion(request):
    user = request.user
    if user.is_pending_deletion():
        user.restore()
        messages.success(request, _('Your account deletion has been cancelled and your account is restored.'))
    else:
        messages.info(request, _('Your account is not scheduled for deletion.'))
    return redirect('profile')


