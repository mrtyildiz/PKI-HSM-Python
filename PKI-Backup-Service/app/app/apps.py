from django.apps import AppConfig
import time
from datetime import datetime, timedelta, timezone
class MyAppConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'app'

    def ready(self):
        from apscheduler.schedulers.background import BackgroundScheduler
        from app.backup import BackupFull

#        time.sleep(3)
        while True:
            scheduler = BackgroundScheduler()
            #scheduler.add_job(BackupFull, 'interval', minutes=60)
            scheduler.add_job(BackupFull, 'interval', seconds=10)
            scheduler.start()
            current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            print(f"Scheduled task executed at {current_time}!")
            #time.sleep(3610)
            time.sleep(12)
            scheduler.shutdown()


# from django.apps import AppConfig


# class AppConfig(AppConfig):
#     default_auto_field = 'django.db.models.BigAutoField'
#     name = 'app'
