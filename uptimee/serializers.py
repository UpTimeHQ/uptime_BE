from rest_framework import serializers
from django.contrib.auth.models import User
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from .models import Company, Equipment, VerificationCode, Task, Notification, CompanyUser
from .models import TaskLog

class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        token['username'] = user.username
        return token

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'first_name', 'last_name']

class CompanySerializer(serializers.ModelSerializer):
    users = UserSerializer(many=True, read_only=True)

    class Meta:
        model = Company
        fields = ['id', 'users', 'name', 'logo', 'address']

class EquipmentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Equipment
        fields = ['id', 'company', 'name', 'equipment_type', 'equipment_id', 'tags', 'location', 'photo', 'status']

class VerificationCodeSerializer(serializers.ModelSerializer):
    class Meta:
        model = VerificationCode
        fields = ['code', 'created_at', 'expires_at']

class TaskSerializer(serializers.ModelSerializer):
    class Meta:
        model = Task
        fields = ['id', 'equipment', 'company', 'task_type', 'description', 'frequency', 'assigned_to', 'due_date', 'status']
        extra_kwargs = {
            'company': {'required': False}  # Make company optional during creation
        }

class NotificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Notification
        fields = ['id', 'user', 'message', 'is_read', 'created_at', 'task']   

class CompanyUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CompanyUser
        fields = ['company', 'user', 'role', 'is_active']


class TaskLogSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)

    class Meta:
        model = TaskLog
        fields = ['id', 'task', 'user', 'comment', 'photo', 'created_at']
        read_only_fields = ['id', 'user', 'created_at']