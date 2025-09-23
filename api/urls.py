# In api/urls.py

from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    TemplateViewSet, RecordViewSet, AuditLogViewSet, UserViewSet, GroupViewSet,
    PrivilegeViewSet, SystemSettingsViewSet, MyTokenObtainPairView, MyProfileViewSet,
    RecordReportViewSet
)
from rest_framework_simplejwt.views import TokenRefreshView


router = DefaultRouter()
router.register(r'templates', TemplateViewSet, basename='template')
router.register(r'records', RecordViewSet, basename='record')
router.register(r'auditlogs', AuditLogViewSet, basename='auditlog')
router.register(r'users', UserViewSet, basename='user')
router.register(r'groups', GroupViewSet, basename='group')
router.register(r'privileges', PrivilegeViewSet, basename='privilege')
router.register(r'system-settings', SystemSettingsViewSet, basename='systemsetting')
router.register(r'my-profile', MyProfileViewSet, basename='my-profile')
router.register(r'reports/records', RecordReportViewSet, basename='record-report')


# The final URL patterns for our API
urlpatterns = [
    path('token/', MyTokenObainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    
    path('', include(router.urls)),
]