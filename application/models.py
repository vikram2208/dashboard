from django.db import models
from django.utils import timezone
import datetime
from phonenumber_field.modelfields import PhoneNumberField
# from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin


class User(models.Model):
    first_name = models.CharField(max_length=30)
    last_name = models.CharField(max_length=30)
    phone_number = PhoneNumberField(blank=True, help_text='Contact phone number')
    email = models.EmailField(max_length=50, blank=False, unique=True)
    password = models.CharField(max_length=200)
    usertype = models.CharField(max_length=20, blank=False)
    created = models.DateTimeField(default=timezone.now)
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    class Meta:
        db_table = 'user'


class Projects(models.Model):
    name = models.CharField(max_length=30, blank=False)
    created = models.DateTimeField(default=timezone.now)

    class Meta:
        db_table = 'project'


class Task(models.Model):
    name = models.CharField(max_length=30, blank=False)
    project = models.ForeignKey(Projects, on_delete=models.CASCADE)
    assigned_to = models.ForeignKey(User, on_delete=models.CASCADE)
    status = models.CharField(max_length=15, blank=False)
    created = models.DateTimeField(default=timezone.now)

    class Meta:
        db_table = 'task'

