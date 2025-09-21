# In api/migrations/0002_seed_gxp_roles.py
from django.db import migrations

PRIVILEGES = {
    "CREATE_EDIT_DRAFT_RECORDS": "Allows creating and editing records in 'Draft' status.",
    "IMPORT_DATA_TO_DRAFT_RECORDS": "Allows importing data into 'Draft' records.",
    "SUBMIT_RECORD_FOR_REVIEW": "Allows submitting a 'Draft' record for review.",
    "PERFORM_REVIEW": "Allows reviewing a submitted record or template.",
    "PERFORM_APPROVAL": "Allows approving a reviewed record or template.",
    "MANAGE_TEMPLATES": "Allows creating, editing, and submitting templates.",
    "IMPORT_DATA_TO_DRAFT_TEMPLATES": "Allows importing data to help design draft templates.",
    "PUBLISH_TEMPLATE": "Allows publishing an 'Approved' template for use.",
    "APPLY_ELECTRONIC_SIGNATURE": "Allows applying an electronic signature to workflow actions.",
    "MANAGE_USERS_AND_ROLES": "Allows creating, editing, and managing user accounts and roles.",
    "MANAGE_SYSTEM_SETTINGS": "Allows configuring system-wide security settings.",
    "VIEW_ALL_RECORDS_TEMPLATES": "Allows read-only viewing of all records and templates.",
    "GENERATE_REPORTS_FOR_RECORDS": "Allows generating reports for records.",
    "VIEW_RECORD_SPECIFIC_AUDIT_TRAIL": "Allows viewing the audit trail for a specific record/template.",
    "VIEW_SYSTEM_WIDE_AUDIT_TRAIL": "Allows viewing the system-wide audit trail for all activities.",
}

ROLES_PRIVILEGES_MAP = {
    "Analyst": [
        "CREATE_EDIT_DRAFT_RECORDS", "IMPORT_DATA_TO_DRAFT_RECORDS", "SUBMIT_RECORD_FOR_REVIEW",
        "APPLY_ELECTRONIC_SIGNATURE", "VIEW_ALL_RECORDS_TEMPLATES", "GENERATE_REPORTS_FOR_RECORDS",
        "VIEW_RECORD_SPECIFIC_AUDIT_TRAIL"
    ],
    "Template Designer": [
        "MANAGE_TEMPLATES", "IMPORT_DATA_TO_DRAFT_TEMPLATES", "APPLY_ELECTRONIC_SIGNATURE",
        "VIEW_ALL_RECORDS_TEMPLATES", "GENERATE_REPORTS_FOR_RECORDS", "VIEW_RECORD_SPECIFIC_AUDIT_TRAIL"
    ],
    "Reviewer": [
        "PERFORM_REVIEW", "APPLY_ELECTRONIC_SIGNATURE", "VIEW_ALL_RECORDS_TEMPLATES",
        "GENERATE_REPORTS_FOR_RECORDS", "VIEW_RECORD_SPECIFIC_AUDIT_TRAIL"
    ],
    "Approver": [
        "PERFORM_APPROVAL", "APPLY_ELECTRONIC_SIGNATURE", "VIEW_ALL_RECORDS_TEMPLATES",
        "GENERATE_REPORTS_FOR_RECORDS", "VIEW_RECORD_SPECIFIC_AUDIT_TRAIL"
    ],
    "Quality Assurance (QA)": [
        "VIEW_ALL_RECORDS_TEMPLATES", "GENERATE_REPORTS_FOR_RECORDS",
        "VIEW_RECORD_SPECIFIC_AUDIT_TRAIL", "VIEW_SYSTEM_WIDE_AUDIT_TRAIL"
    ],
    "Administrator": [
        "PUBLISH_TEMPLATE", "MANAGE_USERS_AND_ROLES", "MANAGE_SYSTEM_SETTINGS",
        "VIEW_ALL_RECORDS_TEMPLATES", "GENERATE_REPORTS_FOR_RECORDS",
        "VIEW_RECORD_SPECIFIC_AUDIT_TRAIL", "VIEW_SYSTEM_WIDE_AUDIT_TRAIL"
    ],
}

def seed_data_and_profiles(apps, schema_editor):
    Group = apps.get_model('auth', 'Group')
    Privilege = apps.get_model('api', 'Privilege')
    GroupProfile = apps.get_model('api', 'GroupProfile')

    for name, description in PRIVILEGES.items():
        Privilege.objects.get_or_create(name=name, defaults={'description': description})

    for role_name, privilege_names in ROLES_PRIVILEGES_MAP.items():
        role, created = Group.objects.get_or_create(name=role_name)
        profile, profile_created = GroupProfile.objects.get_or_create(group=role)
        privileges_for_role = Privilege.objects.filter(name__in=privilege_names)
        profile.privileges.set(privileges_for_role)

class Migration(migrations.Migration):
    dependencies = [('api', '0001_initial')]
    operations = [migrations.RunPython(seed_data_and_profiles)]