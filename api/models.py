# In api/models.py

from django.db import models
from django.contrib.auth.models import User, Group
from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.utils import timezone

TEMPLATE_STATUS_CHOICES = [
    ('DRAFT', 'Draft'),
    ('VERIFIED', 'Verified'),
    ('SUBMITTED_FOR_REVIEW', 'Submitted for Review'),
    ('REVIEWED', 'Reviewed'),
    ('APPROVED', 'Approved'),
    ('REJECTED', 'Rejected'),
    ('RETIRED', 'Retired')
]
RECORD_STATUS_CHOICES = [
    ('DRAFT', 'Draft'),
    ('SUBMITTED_FOR_REVIEW', 'Submitted for Review'),
    ('REVIEWED', 'Reviewed'),
    ('APPROVED', 'Approved'),
    ('REJECTED', 'Rejected'),
    ('CANCELLED', 'Cancelled')
]

class SystemSettings(models.Model):
    enforce_unique_usernames = models.BooleanField(default=True)
    enforce_password_complexity = models.BooleanField(default=True)
    password_complexity_regex = models.CharField(
        max_length=255,
        default="^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[\\W_]).+$",
        help_text="Regex for password complexity. Default checks for at least one lowercase, one uppercase, one number, and one special character."
    )
    username_min_length = models.PositiveIntegerField(default=3)
    username_max_length = models.PositiveIntegerField(default=15)
    username_force_lowercase = models.BooleanField(default=True, help_text="Force all usernames to be saved in lowercase.")
    username_allow_capitals = models.BooleanField(default=True)
    username_allow_numbers = models.BooleanField(default=True)
    allow_user_account_closure = models.BooleanField(default=False, help_text="Allow users to initiate closing their own account.")
    password_prevent_username_sequence = models.BooleanField(default=True, help_text="Block passwords containing 4+ characters of the username.")
    password_expiry_days = models.PositiveIntegerField(default=90)
    password_lockout_attempts = models.PositiveIntegerField(default=5)
    password_lockout_duration = models.PositiveIntegerField(default=15, help_text="Lockout duration in minutes.")
    admin_only_unlock = models.BooleanField(default=True, help_text="If true, only an admin can unlock a locked account.")
    deactivate_idle_user_days = models.PositiveIntegerField(default=180, help_text="Number of days of inactivity before a user account is automatically disabled.")
    password_history_count = models.PositiveIntegerField(default=5, help_text="Number of previous passwords to store and prevent reuse of.")
    password_min_length = models.PositiveIntegerField(default=12)
    password_max_length = models.PositiveIntegerField(default=35)
    session_timeout_minutes = models.PositiveIntegerField(default=15)
    session_require_relogin = models.BooleanField(default=True, help_text="Force re-authentication after session timeout.")
    enforce_single_user_session = models.BooleanField(default=True)
    TIMEZONE_CHOICES = [('UTC', 'UTC'), ('America/New_York', 'America/New_York (EST)'), ('Europe/London', 'Europe/London (GMT)'), ('Asia/Kolkata', 'Asia/Kolkata (IST)')]
    DATE_FORMAT_CHOICES = [('YYYY-MM-DD', 'YYYY-MM-DD'), ('DD-MMM-YYYY', 'DD-MMM-YYYY'), ('MM/DD/YYYY', 'MM/DD/YYYY')]
    TIME_FORMAT_CHOICES = [('24_HOUR', '24-Hour (HH:mm)'), ('12_HOUR', '12-Hour (hh:mm A)')]
    LANGUAGE_CHOICES = [('en', 'English'), ('de', 'German'), ('fr', 'French')]
    time_zone = models.CharField(max_length=50, choices=TIMEZONE_CHOICES, default='UTC')
    date_format = models.CharField(max_length=20, choices=DATE_FORMAT_CHOICES, default='YYYY-MM-DD')
    time_format = models.CharField(max_length=20, choices=TIME_FORMAT_CHOICES, default='24_HOUR')
    language_default = models.CharField(max_length=10, choices=LANGUAGE_CHOICES, default='en')
    editor_spell_check = models.BooleanField(default=True)

    def __str__(self):
        return "System Configuration Settings"
    class Meta:
        verbose_name_plural = "System Settings"

class Template(models.Model):
    # --- THIS IS THE FIX: Removed unique=True ---
    template_id = models.CharField(max_length=255)
    name = models.CharField(max_length=255)
    major_version = models.PositiveIntegerField(default=1)
    minor_version = models.PositiveIntegerField(default=0)
    parent_template = models.ForeignKey('self', on_delete=models.SET_NULL, null=True, blank=True, related_name='versions')
    status = models.CharField(max_length=50, choices=TEMPLATE_STATUS_CHOICES, default='DRAFT')
    document_data = models.JSONField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(User, on_delete=models.PROTECT, related_name='templates_created')
    updated_at = models.DateTimeField(auto_now=True)
    updated_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='templates_updated')
    approved_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        unique_together = ('template_id', 'name', 'major_version', 'minor_version')
        ordering = ['name', '-major_version', '-minor_version']

    def __str__(self):
        return f"{self.name} v{self.major_version}.{self.minor_version}"

    @property
    def version(self):
        return f"v{self.major_version}.{self.minor_version}"

class Record(models.Model):
    template = models.ForeignKey(Template, on_delete=models.PROTECT)
    record_id_display = models.CharField(max_length=100, unique=True, blank=True)
    status = models.CharField(max_length=50, choices=RECORD_STATUS_CHOICES, default='DRAFT')
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(User, on_delete=models.PROTECT, related_name='records_created')
    def save(self, *args, **kwargs):
        if not self.pk and not self.record_id_display:
            current_year = timezone.now().year
            last_record = Record.objects.filter(record_id_display__startswith=f'REC-{current_year}').order_by('record_id_display').last()
            if last_record:
                last_id_num = int(last_record.record_id_display.split('-')[-1])
                new_id_num = last_id_num + 1
            else:
                new_id_num = 1
            self.record_id_display = f'REC-{current_year}-{new_id_num:04d}'
        super().save(*args, **kwargs)
    def __str__(self):
        return self.record_id_display

class RecordData(models.Model):
    record = models.ForeignKey(Record, on_delete=models.CASCADE, related_name='data_entries')
    cell_id = models.CharField(max_length=20)
    cell_value = models.TextField(blank=True, null=True)
    previous_value = models.TextField(blank=True, null=True)

    class Meta:
        unique_together = ('record', 'cell_id')
    def __str__(self):
        return f"Data for Record ID {self.record.id} - Cell {self.cell_id}"

class AuditLog(models.Model):
    timestamp = models.DateTimeField(auto_now_add=True)
    user = models.ForeignKey(User, on_delete=models.PROTECT)
    action = models.CharField(max_length=255)
    content_type = models.ForeignKey(ContentType, on_delete=models.SET_NULL, null=True, blank=True)
    object_id = models.PositiveIntegerField(null=True, blank=True)
    content_object = GenericForeignKey('content_type', 'object_id')
    details = models.TextField()
    reason_for_change = models.CharField(max_length=255, blank=True, null=True)
    previous_value = models.TextField(blank=True, null=True)
    new_value = models.TextField(blank=True, null=True)

    def __str__(self):
        return f"[{self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}] {self.user.username}: {self.action}"

class Privilege(models.Model):
    name = models.CharField(max_length=100, unique=True, help_text="The code name for the privilege, e.g., MANAGE_USERS")
    description = models.CharField(max_length=255, help_text="A user-friendly description of what this privilege allows.")
    def __str__(self):
        return self.name

class GroupProfile(models.Model):
    group = models.OneToOneField(Group, on_delete=models.CASCADE, related_name='profile')
    privileges = models.ManyToManyField(Privilege, blank=True)
    def __str__(self):
        return f"Profile for {self.group.name} role"

@receiver(post_save, sender=Group)
def create_or_update_group_profile(sender, instance, **kwargs):
    GroupProfile.objects.get_or_create(group=instance)

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    password_last_changed = models.DateTimeField(default=timezone.now)
    failed_login_attempts = models.PositiveIntegerField(default=0)
    lockout_until = models.DateTimeField(null=True, blank=True)
    def __str__(self):
        return f"Profile for {self.user.username}"

class PasswordHistory(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='password_history')
    password_hash = models.CharField(max_length=128)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']
        verbose_name_plural = "Password History"

@receiver(post_save, sender=User)
def create_or_update_user_profile(sender, instance, **kwargs):
    UserProfile.objects.get_or_create(user=instance)

class ElectronicSignature(models.Model):
    content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE)
    object_id = models.PositiveIntegerField()
    content_object = GenericForeignKey('content_type', 'object_id')
    signed_by = models.ForeignKey(User, on_delete=models.PROTECT)
    signed_at = models.DateTimeField(auto_now_add=True)
    meaning = models.CharField(max_length=100)
    def __str__(self):
        return f"Signature by {self.signed_by.username} for {self.meaning}"