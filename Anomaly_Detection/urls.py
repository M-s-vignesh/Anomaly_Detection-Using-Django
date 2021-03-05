"""Anomaly_Detection URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from Anomaly_Detection.views import index,index2,index3,index4,index5

urlpatterns = [
    path('admin/', admin.site.urls),
    path('anomaly/',index,name="template1"),
    path('detection/',index2,name="template2"),
    path('abstract/',index3,name="template3"),
    path('list/',index4,name="template4"),
    path('team/',index5,name="template5"),
]
