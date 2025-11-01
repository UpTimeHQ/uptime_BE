from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone

class Company(models.Model):
    users = models.ManyToManyField(User, through='CompanyUser', related_name='companies')
    name = models.CharField(max_length=255)
    logo = models.ImageField(upload_to='company_logos/', blank=True, null=True)
    address = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name

class CompanyUser(models.Model):
    ROLE_CHOICES = (
        ('owner', 'Owner'),
        ('manager', 'Manager'),
        ('supervisor', 'Supervisor'),
        ('technician', 'Technician'),
    )
    company = models.ForeignKey(Company, on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='technician')
    is_active = models.BooleanField(default=True)
    joined_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('company', 'user')

    def __str__(self):
        return f"{self.user.username} - {self.role} in {self.company.name}"

class Equipment(models.Model):
    company = models.ForeignKey(Company, on_delete=models.CASCADE, related_name='equipment')
    name = models.CharField(max_length=255)
    equipment_type = models.CharField(max_length=100)
    equipment_id = models.CharField(max_length=100, unique=True)
    tags = models.JSONField(default=list)
    location = models.CharField(max_length=255, blank=True)
    photo = models.ImageField(upload_to='equipment_photos/', blank=True, null=True)
    status = models.CharField(max_length=50, default='active')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.name} ({self.equipment_id})"

class VerificationCode(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    code = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    is_used = models.BooleanField(default=False)

    def __str__(self):
        return f"Code {self.code} for {self.user.username}"

class Task(models.Model):
    STATUS_CHOICES = (
        ('pending', 'Pending'),
        ('in_progress', 'In Progress'),
        ('completed', 'Completed'),
        ('overdue', 'Overdue'),
    )
    equipment = models.ForeignKey(Equipment, on_delete=models.CASCADE, related_name='tasks')
    company = models.ForeignKey(Company, on_delete=models.CASCADE, related_name='tasks')
    task_type = models.CharField(max_length=100)
    description = models.TextField(blank=True)
    frequency = models.CharField(max_length=50, blank=True)
    assigned_to = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='assigned_tasks')
    due_date = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')

    def __str__(self):
        return f"{self.task_type} for {self.equipment.name}"

class Notification(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='notifications')
    message = models.TextField()
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    task = models.ForeignKey(Task, on_delete=models.CASCADE, null=True, blank=True, related_name='notifications')

    def __str__(self):
        return f"Notification for {self.user.username}: {self.message}"


class TaskLog(models.Model):
    """A log entry for work performed on a Task (digital service logbook)."""
    task = models.ForeignKey(Task, on_delete=models.CASCADE, related_name='logs')
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    comment = models.TextField(blank=True)
    photo = models.ImageField(upload_to='task_logs/', blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Log {self.id} for task {self.task_id} by {self.user.username if self.user else 'unknown'}"