from django.urls import path
from . import views

urlpatterns = [
    path('', views.login_view, name='login'),
    path('home/', views.home_view, name='home'),
    path('logout/', views.log_out, name='logout'),
    path('toggle_detector/', views.toggle_detector, name='toggle_detector'),
    path('network_usage/', views.netowrk_usage, name='network_usage'),
    path('dpi_alerts/', views.dpi_alerts, name='dpi_alerts'),
    path('snort_alerts/', views.snort_alerts, name='snort_alerts')
]