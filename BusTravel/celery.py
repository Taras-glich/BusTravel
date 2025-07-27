import os
from celery import Celery

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'BusTravel.settings')

app = Celery('BusTravel')

app.config_from_object('django.conf:settings', namespace='CELERY')

app.autodiscover_tasks()

@app.task(bind=True)
def debug_task(self):
    print(f'Задача виконана: {self.request!r}')
