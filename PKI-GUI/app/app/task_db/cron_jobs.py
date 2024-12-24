# your_app/tasks/cron_jobs.py
from django_cron import CronJobBase, Schedule
#from ..models import Logs
from django.utils import timezone
import subprocess
import datetime



class CleanLogsJob(CronJobBase):
#    RUN_EVERY_MINS = 60 * 24  # Her gün
    RUN_EVERY_MINS = 1  # Her dakika
    schedule = Schedule(run_every_mins=RUN_EVERY_MINS)
    code = 'app.task_db.cron_jobs'

    def do(self):
        try:
            # Yedekleme dosyasının adı ve yolu
            backup_time = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
            backup_file = f'logs_backup_{backup_time}.json'

            # dumpdata komutunu çalıştır
            command = f"python3 /app/manage.py dumpdata your_app.Log > /opt/BackupLog/{backup_file}"
            subprocess.run(command, shell=True, check=True)

            # Retention Period kontrolü
            retention_period = timezone.now() - self.model.retention_period
            #Logs.objects.filter(created_at__lt=retention_period).delete()

            print(f"Logs model backed up successfully: {backup_file}")
        except subprocess.CalledProcessError as e:
            print(f"Error occurred: {e}")
        except Exception as e:
            print(f"General error occurred: {e}")

        return backup_file
