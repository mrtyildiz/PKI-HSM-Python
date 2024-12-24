from pathlib import Path
import os

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/4.2/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'django-insecure-ka@e*rz0edmo-&!n7+az1)^f47fdtvmyx!y1b*6ev@zs%bf4!_'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = ['*']
#SECURE_SSL_REDIRECT = True
CORS_ALLOWED_ORIGINS = [
    "https://192.168.1.140:8443",
    "https://127.0.0.1:8443",
]


# Application definition

INSTALLED_APPS = [
    'tenant_schemas',
    'django.contrib.contenttypes',
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    "django_extensions",
    'app',
]
# AUTHENTICATION_BACKENDS = [
#     'app.CustomLDAPAuthBackend',
#     'django.contrib.auth.backends.ModelBackend',
#     # Diğer kimlik doğrulama sınıfları
# ]

# # LDAP ayarları
# LDAP_SERVER_IP = '172.16.0.11'
# LDAP_SERVER_PORT = 389
# LDAP_ADMIN_DN = 'cn=admin,dc=procenne,dc=com'
# LDAP_ADMIN_PASSWORD = 'admin'
# LDAP_SEARCH_BASE = 'ou=users,dc=procenne,dc=com'

MIDDLEWARE = [
    'tenant_schemas.middleware.TenantMiddleware',
    'app.middlewares.ClientMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
  #  'app.Lisans.middleware.LicenseMiddleware',
    # #### Two factor ####
    # 'allauth.account.middleware.AccountMiddleware',
    # 'allauth.account.auth_backends.AuthenticationBackend',
    # 'allauth_2fa.auth_backends.Allauth2FABackend',
]
ROOT_URLCONF = 'pki_gui.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [os.path.join(BASE_DIR, 'templates')],
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

WSGI_APPLICATION = 'pki_gui.wsgi.application'


# Database
# https://docs.djangoproject.com/en/4.2/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'tenant_schemas.postgresql_backend',
       # 'ENGINE': 'django.db.backends.postgresql_psycopg2',
        'NAME': os.environ.get("Postgresql_DB"),
        'USER': os.environ.get("Postgresql_User"),
        'PASSWORD': os.environ.get("Postgresql_Password"),
        'HOST': os.environ.get("Postgresql_IP"),
        'PORT': os.environ.get("Postgresql_Port"),
    }
}
TENANT_APPS = [
    'tenant_schemas',
    'django.contrib.contenttypes',
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    "django_extensions",
    'app',
]

SHARED_APPS = [
    'tenant_schemas',
    'django.contrib.contenttypes',
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    "django_extensions",
    'app',
]
#INSTALLED_APPS = TENANT_APPS + SHARED_APPS
TENANT_MODEL = "app.Client"
DATABASE_ROUTERS = ['tenant_schemas.routers.TenantSyncRouter']
DEFAULT_FILE_STORAGE = 'tenant_schemas.storage.TenantFileSystemStorage'

# DATABASES = {
#     'default': {
#         'ENGINE': 'django.db.backends.postgresql_psycopg2',
#         'NAME': 'pki_gui_db',
#         'USER': 'postgres',
#         'PASSWORD': 'postgres',
#         'HOST': '127.0.0.1',
#         'PORT': 5432,
#     }
# }



# Password validation
# https://docs.djangoproject.com/en/4.2/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
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

TIME_ZONE = 'Europe/Istanbul'

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/4.2/howto/static-files/
LOGIN_URL = 'login'
LOGIN_TEMPLATE = 'app/templates/login.html'
LOGOUT_REDIRECT_URL = 'login'
#STATIC_URL = 'static/'
STATIC_URL = '/static/'
STATIC_ROOT = BASE_DIR / "static"
# Default primary key field type
# https://docs.djangoproject.com/en/4.2/ref/settings/#default-auto-field
