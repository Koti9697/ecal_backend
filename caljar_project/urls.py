# In ecal_project/urls.py

from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
    
    # This single line now correctly points to api/urls.py for all API routes,
    # including the token authentication URLs.
    path('api/', include('api.urls')),
]