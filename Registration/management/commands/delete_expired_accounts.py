
from django.core.management.base import BaseCommand
from django.utils import timezone
from Registration.models import User
from datetime import timedelta

class Command(BaseCommand):
    help = 'Permanently delete accounts scheduled for deletion over 30 days ago.'

    def handle(self, *args, **kwargs):
        threshold_date = timezone.now() - timedelta(days=30)
        users_to_delete = User.objects.filter(deleted_at__lte=threshold_date)
        count = users_to_delete.count()
        for user in users_to_delete:
            user.permanent_delete()
        self.stdout.write(self.style.SUCCESS(f'Successfully permanently deleted {count} accounts.'))
