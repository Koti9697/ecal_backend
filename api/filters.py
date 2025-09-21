# In api/filters.py

from django_filters import rest_framework as filters
from .models import AuditLog, Record, Template # Import Template

class AuditLogFilter(filters.FilterSet):
    """
    Enhanced FilterSet for the AuditLog model.
    Allows filtering by username, action, a date range, and the details text.
    """
    user = filters.CharFilter(field_name='user__username', lookup_expr='icontains', label='Username')
    details = filters.CharFilter(lookup_expr='icontains', label='Details contain')

    timestamp_after = filters.DateTimeFilter(field_name="timestamp", lookup_expr='gte')
    timestamp_before = filters.DateTimeFilter(field_name="timestamp", lookup_expr='lte')

    class Meta:
        model = AuditLog
        fields = ['user', 'action', 'details', 'timestamp_after', 'timestamp_before']

# --- NEW: FilterSet for the Template Administration Page ---
class TemplateFilter(filters.FilterSet):
    name = filters.CharFilter(lookup_expr='icontains')
    created_by = filters.CharFilter(field_name='created_by__username', lookup_expr='icontains')
    updated_by = filters.CharFilter(field_name='updated_by__username', lookup_expr='icontains')
    updated_after = filters.DateFilter(field_name='updated_at', lookup_expr='date__gte')
    updated_before = filters.DateFilter(field_name='updated_at', lookup_expr='date__lte')
    
    class Meta:
        model = Template
        fields = ['name', 'status', 'created_by', 'updated_by', 'updated_after', 'updated_before']


class RecordReportFilter(filters.FilterSet):
    template = filters.CharFilter(field_name='template__name', lookup_expr='icontains')
    created_after = filters.DateFilter(field_name='created_at', lookup_expr='date__gte')
    created_before = filters.DateFilter(field_name='created_at', lookup_expr='date__lte')

    class Meta:
        model = Record
        fields = ['status', 'template', 'created_by__username', 'created_after', 'created_before']