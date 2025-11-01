from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView
from .views import CustomTokenObtainPairView, RegisterView, EquipmentListCreateView, EquipmentDetailView, PasswordResetView, VerifyCodeView, CompanyUpdateView, TaskCreateView, TaskListView, LogbookListView, TaskDetailView, TaskCompleteView, NotificationListView, NotificationReadView, ReportListView, UserListView, ReportExportView, UserInviteView
from .views import TaskLogCreateView, TaskLogListView, SyncView, SMSReminderView

urlpatterns = [
    path('auth/login/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('auth/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('auth/register/', RegisterView.as_view(), name='register'),
    path('auth/password-reset/', PasswordResetView.as_view(), name='password_reset'),
    path('auth/verify/', VerifyCodeView.as_view(), name='verify_code'),
    path('onboarding/company/', CompanyUpdateView.as_view(), name='company_update'),
    path('equipment/', EquipmentListCreateView.as_view(), name='equipment_list_create'),
    path('equipment/<pk>/', EquipmentDetailView.as_view(), name='equipment_detail'),
    path('scheduling/task/', TaskCreateView.as_view(), name='task_create'),
    path('tasks/', TaskListView.as_view(), name='task_list'),
    path('logbook/', LogbookListView.as_view(), name='logbook_list'),
    path('tasks/<pk>/', TaskDetailView.as_view(), name='task_detail'),
    path('tasks/<pk>/complete/', TaskCompleteView.as_view(), name='task_complete'),
    path('notifications/', NotificationListView.as_view(), name='notification_list'),
    path('notifications/<pk>/read/', NotificationReadView.as_view(), name='notification_read'),
    path('reports/', ReportListView.as_view(), name='report_list'),
    path('users/', UserListView.as_view(), name='user_list'),
    path('users/invite/', UserInviteView.as_view(), name='user_invite'),
    path('reports/export/', ReportExportView.as_view(), name='report_export'),
    path('logs/', TaskLogListView.as_view(), name='tasklog_list'),
    path('logs/create/', TaskLogCreateView.as_view(), name='tasklog_create'),
    path('sync/', SyncView.as_view(), name='sync'),
    path('reminders/sms/', SMSReminderView.as_view(), name='sms_reminder'),
]