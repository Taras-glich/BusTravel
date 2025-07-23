"""
Django settings for BusTravel project.
"""

from pathlib import Path
from django.utils.translation import gettext_lazy as _

# Build paths
BASE_DIR = Path(__file__).resolve().parent.parent

# Security settings
SECRET_KEY = 'django-insecure-kl33+uc8gees3rsf8087^&lw)82j-&)8+_vh&ne0fte)(+1qu&'
DEBUG = True
ALLOWED_HOSTS = []

# Application definition
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'Registration.apps.RegistrationConfig',
    'django_recaptcha',
    'celery',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.locale.LocaleMiddleware',  # Для підтримки i18n
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'BusTravel.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                'django.template.context_processors.i18n',  # Для підтримки i18n
            ],
        },
    },
]

WSGI_APPLICATION = 'BusTravel.wsgi.application'

# Database
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}

# Password validation
AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
        'OPTIONS': {
            'min_length': 8,
        }
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

# Internationalization
LANGUAGE_CODE = 'en'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_L10N = True
USE_TZ = True

LANGUAGES = [
    ('en', _('English')),
    ('uk', _('Ukrainian')),
]

LOCALE_PATHS = [
    BASE_DIR / 'locale',
]

# Authentication
AUTH_USER_MODEL = 'Registration.User'
LOGIN_URL = 'login'
LOGIN_REDIRECT_URL = 'profile'
LOGOUT_REDIRECT_URL = 'home'

# Session settings
SESSION_COOKIE_AGE = 1209600  # 2 тижні
SESSION_SAVE_EVERY_REQUEST = True
SESSION_COOKIE_SECURE = False  # True для production з HTTPS
CSRF_COOKIE_SECURE = False    # True для production з HTTPS

# Two-factor authentication
TWO_FACTOR_CODE_LENGTH = 6
TWO_FACTOR_CODE_VALIDITY = 300  # 5 хвилин

# Static files
STATIC_URL = 'static/'
STATICFILES_DIRS = [BASE_DIR / 'static']  # Додаткові статичні файли

# Media files
MEDIA_URL = 'media/'
MEDIA_ROOT = BASE_DIR / 'media'

# Email settings
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = 'bustravel1546@gmail.com'
EMAIL_HOST_PASSWORD = 'qgmc uxrr odfb yasx'
DEFAULT_FROM_EMAIL = 'bustravel1546@gmail.com'

# Default primary key field
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# Security headers (для production)
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'

RECAPTCHA_PUBLIC_KEY = '6Lfd5mIrAAAAAHeQf1hOY8Xf8-Z0lUfBf5b2INFZ'
RECAPTCHA_PRIVATE_KEY = '6Lfd5mIrAAAAAIXf8lIj6x4EO2uRZ86q_vBYIv65'
NOCAPTCHA = True

AUTHENTICATION_BACKENDS = [
    'Registration.backends.EmailOrUsernameModelBackend',
    'django.contrib.auth.backends.ModelBackend',
]

CELERY_BROKER_URL = 'redis://localhost:6379/0'
CELERY_RESULT_BACKEND = 'redis://localhost:6379/0'

