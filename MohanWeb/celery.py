import os
from celery import Celery


os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'MohanWeb.settings')

celery_app = Celery('MohanWeb')
celery_app.config_from_object('django.conf:settings', namespace='CELERY')
celery_app.autodiscover_tasks()
