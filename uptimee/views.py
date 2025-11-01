from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, generics
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_simplejwt.views import TokenObtainPairView
from django.contrib.auth.models import User
from django.core.mail import send_mail
from django.conf import settings
from django.utils import timezone
from django.http import HttpResponse
import csv
import io
from datetime import timedelta
import random
import string
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from .models import Company, CompanyUser, Equipment, VerificationCode, Task, Notification, TaskLog
from .serializers import CustomTokenObtainPairSerializer, UserSerializer, CompanySerializer, EquipmentSerializer, VerificationCodeSerializer, TaskSerializer, NotificationSerializer, TaskLogSerializer

class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer

class RegisterView(APIView):
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['username', 'email', 'password', 'company_name'],
            properties={
                'username': openapi.Schema(type=openapi.TYPE_STRING, description='Username for the new user'),
                'email': openapi.Schema(type=openapi.TYPE_STRING, format=openapi.FORMAT_EMAIL, description='User email'),
                'password': openapi.Schema(type=openapi.TYPE_STRING, description='User password'),
                'company_name': openapi.Schema(type=openapi.TYPE_STRING, description='Name of the company'),
                'first_name': openapi.Schema(type=openapi.TYPE_STRING, description='First name (optional)'),
                'last_name': openapi.Schema(type=openapi.TYPE_STRING, description='Last name (optional)'),
                'company_address': openapi.Schema(type=openapi.TYPE_STRING, description='Company address (optional)'),
            },
        ),
        responses={
            201: openapi.Response('User and company created', openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'user': openapi.Schema(type=openapi.TYPE_OBJECT, ref='#/components/schemas/User'),
                    'company': openapi.Schema(type=openapi.TYPE_OBJECT, ref='#/components/schemas/Company'),
                }
            )),
            400: 'Bad Request'
        }
    )
    def post(self, request):
        data = request.data
        required_fields = ['username', 'email', 'password', 'company_name']
        missing_fields = [field for field in required_fields if field not in data or not data[field]]
        if missing_fields:
            return Response({'error': f'Missing required fields: {", ".join(missing_fields)}'}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            user = User.objects.create_user(
                username=data['username'],
                email=data['email'],
                password=data['password'],
                first_name=data.get('first_name', ''),
                last_name=data.get('last_name', '')
            )
            company = Company.objects.create(
                name=data['company_name'],
                address=data.get('company_address', '')
            )
            # Create CompanyUser entry for the owner
            CompanyUser.objects.create(
                company=company,
                user=user,
                role='owner'
            )
            return Response({
                'user': UserSerializer(user).data,
                'company': CompanySerializer(company).data
            }, status=status.HTTP_201_CREATED)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

class PasswordResetView(APIView):
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['email'],
            properties={
                'email': openapi.Schema(type=openapi.TYPE_STRING, format=openapi.FORMAT_EMAIL, description='User email for password reset'),
            },
        ),
        responses={
            200: 'Password reset email sent',
            400: 'Invalid email'
        }
    )
    def post(self, request):
        email = request.data.get('email')
        if not email:
            return Response({'error': 'Email is required'}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            user = User.objects.get(email=email)
            code = ''.join(random.choices(string.digits, k=6))
            expires_at = timezone.now() + timedelta(minutes=30)
            VerificationCode.objects.create(user=user, code=code, expires_at=expires_at)
            
            send_mail(
                'UpTime Password Reset',
                f'Your verification code is: {code}. It expires in 30 minutes.',
                settings.EMAIL_HOST_USER,
                [email],
                fail_silently=False,
            )
            return Response({'message': 'Password reset email sent'}, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({'error': 'Email not found'}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

class VerifyCodeView(APIView):
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['email', 'code', 'new_password'],
            properties={
                'email': openapi.Schema(type=openapi.TYPE_STRING, format=openapi.FORMAT_EMAIL, description='User email'),
                'code': openapi.Schema(type=openapi.TYPE_STRING, description='Verification code'),
                'new_password': openapi.Schema(type=openapi.TYPE_STRING, description='New password'),
            },
        ),
        responses={
            200: 'Password reset successful',
            400: 'Invalid code or email'
        }
    )
    def post(self, request):
        email = request.data.get('email')
        code = request.data.get('code')
        new_password = request.data.get('new_password')
        
        if not all([email, code, new_password]):
            return Response({'error': 'Email, code, and new password are required'}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            user = User.objects.get(email=email)
            verification = VerificationCode.objects.get(user=user, code=code, is_used=False, expires_at__gt=timezone.now())
            user.set_password(new_password)
            user.save()
            verification.is_used = True
            verification.save()
            return Response({'message': 'Password reset successful'}, status=status.HTTP_200_OK)
        except (User.DoesNotExist, VerificationCode.DoesNotExist):
            return Response({'error': 'Invalid email or code'}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

class CompanyUpdateView(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        request_body=CompanySerializer,
        responses={
            200: CompanySerializer,
            400: 'Bad Request',
            401: 'Unauthorized',
            404: 'Not Found'
        }
    )
    def post(self, request):
        try:
            company = Company.objects.get(users=request.user)
            serializer = CompanySerializer(company, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Company.DoesNotExist:
            return Response({'error': 'Company not found for this user'}, status=status.HTTP_404_NOT_FOUND)

class EquipmentListCreateView(generics.ListCreateAPIView):
    queryset = Equipment.objects.all()
    serializer_class = EquipmentSerializer
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        request_body=EquipmentSerializer,
        responses={
            201: EquipmentSerializer,
            400: 'Bad Request',
            401: 'Unauthorized'
        }
    )
    def post(self, request, *args, **kwargs):
        return super().post(request, *args, **kwargs)

    def get_queryset(self):
        # Avoid DB access during schema generation and when unauthenticated
        if getattr(self, 'swagger_fake_view', False):
            return Equipment.objects.none()
        user = getattr(self.request, 'user', None)
        if not user or not getattr(user, 'is_authenticated', False):
            return Equipment.objects.none()
        company = Company.objects.filter(users=user).first()
        if not company:
            return Equipment.objects.none()
        # Basic filtering support: name, equipment_id, status, tag
        queryset = Equipment.objects.filter(company=company)
        name = self.request.query_params.get('name')
        equipment_id = self.request.query_params.get('equipment_id')
        status = self.request.query_params.get('status')
        tag = self.request.query_params.get('tag')
        if name:
            queryset = queryset.filter(name__icontains=name)
        if equipment_id:
            queryset = queryset.filter(equipment_id__iexact=equipment_id)
        if status:
            queryset = queryset.filter(status__iexact=status)
        if tag:
            queryset = queryset.filter(tags__contains=[tag])
        return queryset

class EquipmentDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Equipment.objects.all()
    serializer_class = EquipmentSerializer
    permission_classes = [IsAuthenticated]
    lookup_field = 'pk'

    @swagger_auto_schema(
        responses={
            200: EquipmentSerializer,
            404: 'Not Found',
            401: 'Unauthorized'
        }
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)

    def get_queryset(self):
        # Avoid DB access during schema generation and when unauthenticated
        if getattr(self, 'swagger_fake_view', False):
            return Equipment.objects.none()
        user = getattr(self.request, 'user', None)
        if not user or not getattr(user, 'is_authenticated', False):
            return Equipment.objects.none()
        company = Company.objects.filter(users=user).first()
        if not company:
            return Equipment.objects.none()
        return Equipment.objects.filter(company=company)

class TaskCreateView(generics.CreateAPIView):
    queryset = Task.objects.all()
    serializer_class = TaskSerializer
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        request_body=TaskSerializer,
        responses={
            201: TaskSerializer,
            400: 'Bad Request',
            401: 'Unauthorized'
        }
    )
    def post(self, request, *args, **kwargs):
        try:
            company = Company.objects.get(users=request.user)
        except Company.DoesNotExist:
            return Response({'error': 'Company not found for this user'}, status=status.HTTP_404_NOT_FOUND)
        
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            # Ensure assigned_to user is in the same company
            assigned_to_id = serializer.validated_data.get('assigned_to')
            if assigned_to_id:
                try:
                    assigned_user = User.objects.get(id=assigned_to_id.id)
                    if not CompanyUser.objects.filter(company=company, user=assigned_user).exists():
                        return Response({'error': 'Assigned user must be in the same company'}, status=status.HTTP_400_BAD_REQUEST)
                except User.DoesNotExist:
                    return Response({'error': 'Assigned user not found'}, status=status.HTTP_400_BAD_REQUEST)
            serializer.save(company=company)
            Notification.objects.create(
                user=request.user,
                message=f"New task created: {serializer.validated_data['task_type']} for equipment {serializer.validated_data['equipment'].name}",
                task=Task.objects.get(id=serializer.data['id'])
            )
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class TaskListView(generics.ListAPIView):
    queryset = Task.objects.all()
    serializer_class = TaskSerializer
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        responses={
            200: TaskSerializer(many=True),
            401: 'Unauthorized'
        },
        manual_parameters=[
            openapi.Parameter('status', openapi.IN_QUERY, description="Filter by task status", type=openapi.TYPE_STRING),
            openapi.Parameter('equipment', openapi.IN_QUERY, description="Filter by equipment ID", type=openapi.TYPE_INTEGER),
        ]
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)

    def get_queryset(self):
        # Avoid DB access during schema generation and when unauthenticated
        if getattr(self, 'swagger_fake_view', False):
            return Task.objects.none()
        user = getattr(self.request, 'user', None)
        if not user or not getattr(user, 'is_authenticated', False):
            return Task.objects.none()
        company = Company.objects.filter(users=user).first()
        if not company:
            return Task.objects.none()
        queryset = Task.objects.filter(company=company)
        status = self.request.query_params.get('status')
        equipment_id = self.request.query_params.get('equipment')
        if status:
            queryset = queryset.filter(status=status)
        if equipment_id:
            queryset = queryset.filter(equipment_id=equipment_id)
        return queryset

class LogbookListView(generics.ListAPIView):
    queryset = Task.objects.filter(status='completed')
    serializer_class = TaskSerializer
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        responses={
            200: TaskSerializer(many=True),
            401: 'Unauthorized'
        },
        manual_parameters=[
            openapi.Parameter('equipment', openapi.IN_QUERY, description="Filter by equipment ID", type=openapi.TYPE_INTEGER),
            openapi.Parameter('start_date', openapi.IN_QUERY, description="Filter by start date (YYYY-MM-DD)", type=openapi.TYPE_STRING, format=openapi.FORMAT_DATE),
        ]
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)

    def get_queryset(self):
        # Avoid DB access during schema generation and when unauthenticated
        if getattr(self, 'swagger_fake_view', False):
            return Task.objects.none()
        user = getattr(self.request, 'user', None)
        if not user or not getattr(user, 'is_authenticated', False):
            return Task.objects.none()
        company = Company.objects.filter(users=user).first()
        if not company:
            return Task.objects.none()
        queryset = Task.objects.filter(company=company, status='completed')
        equipment_id = self.request.query_params.get('equipment')
        start_date = self.request.query_params.get('start_date')
        if equipment_id:
            queryset = queryset.filter(equipment_id=equipment_id)
        if start_date:
            queryset = queryset.filter(created_at__gte=start_date)
        return queryset

class TaskDetailView(generics.RetrieveAPIView):
    queryset = Task.objects.all()
    serializer_class = TaskSerializer
    permission_classes = [IsAuthenticated]
    lookup_field = 'pk'

    @swagger_auto_schema(
        responses={
            200: TaskSerializer,
            404: 'Not Found',
            401: 'Unauthorized'
        }
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)

    def get_queryset(self):
        # Avoid DB access during schema generation and when unauthenticated
        if getattr(self, 'swagger_fake_view', False):
            return Task.objects.none()
        user = getattr(self.request, 'user', None)
        if not user or not getattr(user, 'is_authenticated', False):
            return Task.objects.none()
        company = Company.objects.filter(users=user).first()
        if not company:
            return Task.objects.none()
        return Task.objects.filter(company=company)

class TaskCompleteView(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        responses={
            200: TaskSerializer,
            404: 'Not Found',
            401: 'Unauthorized'
        }
    )
    def patch(self, request, pk):
        try:
            company = Company.objects.get(users=request.user)
            task = Task.objects.get(pk=pk, company=company)
            task.status = 'completed'
            task.save()
            Notification.objects.create(
                user=request.user,
                message=f"Task completed: {task.task_type} for equipment {task.equipment.name}"
            )
            return Response(TaskSerializer(task).data, status=status.HTTP_200_OK)
        except (Company.DoesNotExist, Task.DoesNotExist):
            return Response({'error': 'Task not found'}, status=status.HTTP_404_NOT_FOUND)

class NotificationListView(generics.ListAPIView):
    queryset = Notification.objects.all()
    serializer_class = NotificationSerializer
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        responses={
            200: NotificationSerializer(many=True),
            401: 'Unauthorized'
        },
        manual_parameters=[
            openapi.Parameter('is_read', openapi.IN_QUERY, description="Filter by read status", type=openapi.TYPE_BOOLEAN),
        ]
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)

    def get_queryset(self):
        # Avoid DB access during schema generation and when unauthenticated
        if getattr(self, 'swagger_fake_view', False):
            return Notification.objects.none()
        user = getattr(self.request, 'user', None)
        if not user or not getattr(user, 'is_authenticated', False):
            return Notification.objects.none()
        queryset = Notification.objects.filter(user=user)
        is_read = self.request.query_params.get('is_read')
        if is_read is not None:
            queryset = queryset.filter(is_read=is_read.lower() == 'true')
        return queryset

class NotificationReadView(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        responses={
            200: NotificationSerializer,
            404: 'Not Found',
            401: 'Unauthorized'
        }
    )
    def patch(self, request, pk):
        try:
            notification = Notification.objects.get(pk=pk, user=request.user)
            notification.is_read = True
            notification.save()
            return Response(NotificationSerializer(notification).data, status=status.HTTP_200_OK)
        except Notification.DoesNotExist:
            return Response({'error': 'Notification not found'}, status=status.HTTP_404_NOT_FOUND)

class ReportListView(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        responses={
            200: openapi.Response('Report data', openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'total_tasks': openapi.Schema(type=openapi.TYPE_INTEGER),
                    'completed_tasks': openapi.Schema(type=openapi.TYPE_INTEGER),
                    'compliance_percentage': openapi.Schema(type=openapi.TYPE_NUMBER),
                }
            )),
            401: 'Unauthorized'
        }
    )
    def get(self, request):
        company = Company.objects.get(users=request.user)
        tasks = Task.objects.filter(company=company)
        total_tasks = tasks.count()
        completed_tasks = tasks.filter(status='completed').count()
        compliance_percentage = (completed_tasks / total_tasks * 100) if total_tasks > 0 else 0
        return Response({
            'total_tasks': total_tasks,
            'completed_tasks': completed_tasks,
            'compliance_percentage': round(compliance_percentage, 2)
        }, status=status.HTTP_200_OK)

class UserListView(generics.ListAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        responses={
            200: UserSerializer(many=True),
            401: 'Unauthorized'
        }
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)

    def get_queryset(self):
        # Avoid DB access during schema generation and when unauthenticated
        if getattr(self, 'swagger_fake_view', False):
            return User.objects.none()
        user = getattr(self.request, 'user', None)
        if not user or not getattr(user, 'is_authenticated', False):
            return User.objects.none()
        company = Company.objects.filter(users=user).first()
        if not company:
            return User.objects.none()
        return User.objects.filter(companyuser__company=company, companyuser__is_active=True)

class ReportExportView(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        responses={
            200: openapi.Response('Exported report data', TaskSerializer(many=True)),
            401: 'Unauthorized'
        },
        manual_parameters=[
            openapi.Parameter('start_date', openapi.IN_QUERY, description="Filter by start date (YYYY-MM-DD)", type=openapi.TYPE_STRING, format=openapi.FORMAT_DATE),
            openapi.Parameter('end_date', openapi.IN_QUERY, description="Filter by end date (YYYY-MM-DD)", type=openapi.TYPE_STRING, format=openapi.FORMAT_DATE),
        ]
    )
    def get(self, request):
        company = Company.objects.get(users=request.user)
        tasks = Task.objects.filter(company=company)
        start_date = request.query_params.get('start_date')
        end_date = request.query_params.get('end_date')
        if start_date:
            tasks = tasks.filter(created_at__gte=start_date)
        if end_date:
            tasks = tasks.filter(created_at__lte=end_date)
        # Support CSV export via ?format=csv
        export_format = request.query_params.get('format')
        if export_format and export_format.lower() == 'csv':
            # Stream CSV
            buffer = io.StringIO()
            writer = csv.writer(buffer)
            # header
            writer.writerow(['id', 'equipment', 'company', 'task_type', 'description', 'assigned_to', 'due_date', 'status', 'created_at'])
            for t in tasks:
                writer.writerow([
                    t.id,
                    t.equipment.name if t.equipment else '',
                    t.company.name if t.company else '',
                    t.task_type,
                    (t.description or '').replace('\n', ' '),
                    t.assigned_to.username if t.assigned_to else '',
                    t.due_date.isoformat() if t.due_date else '',
                    t.status,
                    t.created_at.isoformat() if t.created_at else '',
                ])
            resp = HttpResponse(buffer.getvalue(), content_type='text/csv')
            resp['Content-Disposition'] = 'attachment; filename="tasks_export.csv"'
            return resp

        serializer = TaskSerializer(tasks, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

class UserInviteView(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['email', 'role'],
            properties={
                'email': openapi.Schema(type=openapi.TYPE_STRING, format=openapi.FORMAT_EMAIL, description='Email of the user to invite'),
                'role': openapi.Schema(type=openapi.TYPE_STRING, description='Role for the invited user (technician, supervisor, manager, owner)'),
            },
        ),
        responses={
            201: 'Invitation sent',
            400: 'Bad Request',
            401: 'Unauthorized'
        }
    )
    def post(self, request):
        email = request.data.get('email')
        role = request.data.get('role')
        if not all([email, role]):
            return Response({'error': 'Email and role are required'}, status=status.HTTP_400_BAD_REQUEST)
        
        if role not in dict(CompanyUser.ROLE_CHOICES):
            return Response({'error': 'Invalid role'}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            company = Company.objects.get(users=request.user)
            # Check if user already exists
            try:
                invited_user = User.objects.get(email=email)
                CompanyUser.objects.create(company=company, user=invited_user, role=role)
            except User.DoesNotExist:
                # For simplicity, create user (in production, send invite email)
                invited_user = User.objects.create_user(username=email.split('@')[0], email=email, password='temp_password')
                CompanyUser.objects.create(company=company, user=invited_user, role=role)
            
            send_mail(
                'UpTime Invitation',
                f'You have been invited to join {company.name} as {role}. Login at http://127.0.0.1:8000 with username {invited_user.username} and password temp_password.',
                settings.EMAIL_HOST_USER,
                [email],
                fail_silently=False,
            )
            return Response({'message': 'Invitation sent successfully'}, status=status.HTTP_201_CREATED)
        except Company.DoesNotExist:
            return Response({'error': 'Company not found'}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)


class TaskLogCreateView(generics.CreateAPIView):
    """Create a log entry for a task (digital service logbook)."""
    serializer_class = TaskLogSerializer
    permission_classes = [IsAuthenticated]
    parser_classes = [generics.mixins.CreateModelMixin] if False else []

    def perform_create(self, serializer):
        user = self.request.user
        task = serializer.validated_data.get('task')
        # Ensure task belongs to user's company
        company = Company.objects.filter(users=user).first()
        if not company or task.company_id != company.id:
            raise PermissionError('Task not found for this user')
        serializer.save(user=user)


class TaskLogListView(generics.ListAPIView):
    serializer_class = TaskLogSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        # List logs for a task or company
        if getattr(self, 'swagger_fake_view', False):
            return TaskLog.objects.none()
        user = getattr(self.request, 'user', None)
        if not user or not user.is_authenticated:
            return TaskLog.objects.none()
        company = Company.objects.filter(users=user).first()
        if not company:
            return TaskLog.objects.none()
        task_id = self.request.query_params.get('task')
        qs = TaskLog.objects.filter(task__company=company)
        if task_id:
            qs = qs.filter(task_id=task_id)
        return qs.order_by('-created_at')


class SyncView(APIView):
    """Simple sync endpoint: client provides last_sync ISO timestamp and receives changed equipment, tasks, and logs."""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        last_sync = request.query_params.get('last_sync')
        user = request.user
        company = Company.objects.filter(users=user).first()
        if not company:
            return Response({'error': 'Company not found'}, status=status.HTTP_400_BAD_REQUEST)
        if last_sync:
            try:
                from django.utils.dateparse import parse_datetime
                dt = parse_datetime(last_sync)
            except Exception:
                dt = None
        else:
            dt = None

        def since(qs):
            return qs if not dt else qs.filter(created_at__gt=dt)

        equipments = since(Equipment.objects.filter(company=company))
        tasks = since(Task.objects.filter(company=company))
        logs = since(TaskLog.objects.filter(task__company=company))

        data = {
            'equipments': EquipmentSerializer(equipments, many=True).data,
            'tasks': TaskSerializer(tasks, many=True).data,
            'logs': TaskLogSerializer(logs, many=True).data,
            'server_time': timezone.now().isoformat(),
        }
        return Response(data)


class SMSReminderView(APIView):
    """Stub endpoint to trigger SMS/WhatsApp reminders for a task. In prod, wire to gateway."""
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['task_id', 'message'],
            properties={
                'task_id': openapi.Schema(type=openapi.TYPE_INTEGER),
                'message': openapi.Schema(type=openapi.TYPE_STRING),
            }
        ),
        responses={200: 'Reminder queued'}
    )
    def post(self, request):
        task_id = request.data.get('task_id')
        message = request.data.get('message')
        try:
            task = Task.objects.get(id=task_id)
        except Task.DoesNotExist:
            return Response({'error': 'Task not found'}, status=status.HTTP_404_NOT_FOUND)
        # Create Notification (acts as queued reminder); real gateway integration would be here
        Notification.objects.create(user=request.user, message=message, task=task)
        return Response({'message': 'Reminder queued (stub)'}, status=status.HTTP_200_OK)