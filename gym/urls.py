from django.urls import path, include
from django.contrib.auth import views as auth_views
from . import views
from .views import CustomPasswordResetView, CustomPasswordResetConfirmView
from django.contrib.auth.views import PasswordResetDoneView, PasswordResetCompleteView


urlpatterns = [
    path('', views.home, name='home'),  # Homepage
    path('test_email/', views.test_email_view, name='test_email'),
    path('register/', views.register_view, name='register'),
    path('email_verification/', views.email_verification, name='email_verification'),
    path('activate/<uidb64>/<token>/', views.activate, name='activate'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('profile/', views.profile, name='profile'),
    path('login/', views.login_view, name='login'),
    path('change_password/', views.change_password_view, name='change_password'),
    path('password_reset/', CustomPasswordResetView.as_view(), name='password_reset'),
    path('password_reset/done/', auth_views.PasswordResetDoneView.as_view(template_name='password_reset_done.html'), name='password_reset_done'),
    path('reset/<uidb64>/<token>/', CustomPasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    path('reset/done/', auth_views.PasswordResetCompleteView.as_view(template_name='password_reset_complete.html'), name='password_reset_complete'),
    path('logout/', views.logout_view, name='logout'),
    # ... other URLs ...    # Include app URLs
    # Password Reset URLs
]   