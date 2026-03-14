# core/urls.py

from django.urls import path
from .views import FileUploadAPI

urlpatterns = [
    path("api/upload/", FileUploadAPI.as_view())
]