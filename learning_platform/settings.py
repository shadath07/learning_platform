"""
Django settings for learning_platform project.

Generated by 'django-admin startproject' using Django 4.2.4.

For more information on this file, see
https://docs.djangoproject.com/en/4.2/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/4.2/ref/settings/
"""

from pathlib import Path
import os
from datetime import timedelta

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/4.2/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'django-insecure-5_!0r%$j)m-#n!25v-!onuzgc6co%$i^9w#lb$iwg*49pl#x7t'

# SECURITY WARNING: don't run with debug turned on in production!
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
    'django_password_validators',
    'paypal.standard',
    'courses',
    'rest_framework',
    'courses.api',
    'rest_framework_simplejwt'
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'learning_platform.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR/'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'learning_platform.wsgi.application'


# Database
# https://docs.djangoproject.com/en/4.2/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql_psycopg2',
        'NAME': 'online_platform',
        'USER': 'shad',
        'PASSWORD': '@Shad1234',
        'HOST': 'localhost',
        'PORT': ''
    }
}

# Media settings
MEDIA_URL = '/media/'
MEDIA_ROOT = os.path.join(BASE_DIR, 'media')

# Password validation
# https://docs.djangoproject.com/en/4.2/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django_password_validators.password_character_requirements.password_validation.PasswordCharacterValidator',
        'OPTIONS': {
             'min_length_digit': 0, 
             'min_length_alpha': 2, 
             'min_length_special': 1, 
             'min_length_lower': 1,  
             'min_length_upper': 1,  
             'special_characters': "~!@#$%^&*()_+{}\":;'[]"
        }
    },
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
# https://docs.djangoproject.com/en/4.2/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/4.2/howto/static-files/

STATIC_URL = '/static/'
STATICFILES_DIRS = [BASE_DIR / "static"]

# Default primary key field type
# https://docs.djangoproject.com/en/4.2/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'


# Email Configuration
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = 'kingshad715@gmail.com'
EMAIL_HOST_PASSWORD = 'axak xjlu nzcr phec'
DEFAULT_FROM_EMAIL = 'kingshad715@gmail.com'  # Set your default "from" address

AUTH_USER_MODEL = 'courses.CustomUser'

AUTHENTICATION_BACKENDS = [
    'courses.backends.EmailBackend',
    'django.contrib.auth.backends.ModelBackend',
]

# To disable the login users when on the admin page .
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
        },
    },
    'root': {
        'handlers': ['console'],
        'level': 'DEBUG',  
    },
}
LOGIN_REDIRECT_URL = 'home'


PAYPAL_RECEIVER_EMAIL = 'shad2@gmail.com'
PAYPAL_TEST = True  # Set to False in production
PAYPAL_IMAGE = 'your-logo-image-url'  # Optional: Your logo for PayPal checkout page
PAYPAL_CLIENT_ID = 'ARKM-OwXbSs7TqUrlZbzAtFTfzEwemDQWm8UdNSiatYTpWmCk6dDtiYe5hFij7nTA7uCKYCA8W71VSNI'
PAYPAL_CLIENT_SECRET = 'ENivQ1H61uPNxIQdS3RzloQFSxNSFk8NGFNoEYkKs9wm4UrDBdUqrQxTLYQTv4gGm5Q4wZvv4wYqVwf6'
PAYPAL_IPN_URL = 'https://www.sandbox.paypal.com/cgi-bin/webscr'


# JWT Authentication configurations
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ],
}
SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME':timedelta(minutes=45),
    'REFRESH_TOKEN_LIFETIME':timedelta(days=1),
    'ROTATE_REFRESH_TOKENS':False,
}


# This is the Global PageNumberPagination settings for all the views.

REST_FRAMEWORK = {
    'DEFAULT_PAGINATION_CLASS' : 'rest_framework.pagination.PageNumberPagination',
    'PAGE_SIZE' : 5,
}


# Disabled csrf protection for testing
# Need to enable csrf protection in production
# CSRF_COOKIE_SECURE = False
# CSRF_COOKIE_SAMESITE = 'Lax'