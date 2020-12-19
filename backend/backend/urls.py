from django.contrib import admin
from django.contrib.auth import views

from django.urls import path, include

from webmail.views import RegisterView

urlpatterns = [
    path('', include('webmail.urls')),
    path('accounts/login/', views.LoginView.as_view(template_name='webmail/login.html'), name='login'),
    path('accounts/logout/', views.LogoutView.as_view(next_page='login'), name='logout'),
    path('accounts/register/', RegisterView.as_view(), name='register'),
    path('admin/', admin.site.urls),
]
