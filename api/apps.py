# In ecal_backend/api/apps.py

from django.apps import AppConfig

class ApiConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'api'

    def ready(self):
        # This line ensures that the signals in models.py are connected
        # when the Django application starts.
        import api.models