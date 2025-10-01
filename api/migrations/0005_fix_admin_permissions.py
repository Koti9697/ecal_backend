# In api/migrations/0005_fix_admin_permissions.py

from django.db import migrations

ADMIN_PRIVILEGES = [
    "PUBLISH_TEMPLATE", 
    "MANAGE_USERS_AND_ROLES", 
    "MANAGE_SYSTEM_SETTINGS",
    "VIEW_ALL_RECORDS_TEMPLATES", 
    "GENERATE_REPORTS_FOR_RECORDS",
    "VIEW_RECORD_SPECIFIC_AUDIT_TRAIL", 
    "VIEW_SYSTEM_WIDE_AUDIT_TRAIL"
]

def fix_administrator_permissions(apps, schema_editor):
    Group = apps.get_model('auth', 'Group')
    Privilege = apps.get_model('api', 'Privilege')
    GroupProfile = apps.get_model('api', 'GroupProfile')

    try:
        # Get the Administrator group and its profile
        admin_group = Group.objects.get(name='Administrator')
        admin_profile, created = GroupProfile.objects.get_or_create(group=admin_group)
        
        # Get the privilege objects that should be assigned
        privileges_for_admin = Privilege.objects.filter(name__in=ADMIN_PRIVILEGES)
        
        # Set the correct privileges. This is idempotent and safe to run multiple times.
        admin_profile.privileges.set(privileges_for_admin)
        
    except Group.DoesNotExist:
        # If the Administrator group doesn't exist for some reason, this
        # migration will do nothing, preventing an error.
        pass

class Migration(migrations.Migration):

    dependencies = [
        ('api', '0004_template_approved_at'),
    ]

    operations = [
        migrations.RunPython(fix_administrator_permissions),
    ]