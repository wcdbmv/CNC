from django.http import HttpResponseRedirect
from django.urls import path

from webmail import views

app_name = 'webmail'

urlpatterns = [
    path('', lambda r: HttpResponseRedirect('inbox/')),
    path('inbox/', views.InboxView.as_view(), name='inbox'),
    path('outbox/', views.OutboxView.as_view(), name='outbox'),
    path('message/<int:pk>/', views.MessageDetailView.as_view(), name='message'),
    path('message/<int:pk>/delete/', views.MessageDeleteView.as_view(), name='message-delete'),
]
