from django.contrib import admin
from .models import Template, Record, RecordData, AuditLog, SystemSettings

# Register your models here.
admin.site.register(Template)
admin.site.register(Record)
admin.site.register(RecordData)
admin.site.register(AuditLog)
# NEW: Register the SystemSettings model
admin.site.register(SystemSettings)
