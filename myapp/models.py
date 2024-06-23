from django.contrib.auth.models import AbstractUser, Group, Permission
from django.db import models
import pyotp
from .utils import validate_phone_number




class CustomUser(AbstractUser):
    otp_secret = models.CharField(max_length=16, default=pyotp.random_base32)
    phone_number = models.CharField(max_length=15, validators=[validate_phone_number], blank=True, null=True)
    use_sms_2fa = models.BooleanField(default=False)

    groups = models.ManyToManyField(
        Group,
        related_name='customuser_set',  # Change this related_name to avoid clash
        blank=True,
        help_text='The groups this user belongs to.',
        related_query_name='customuser',
    )
    user_permissions = models.ManyToManyField(
        Permission,
        related_name='customuser_set',  # Change this related_name to avoid clash
        blank=True,
        help_text='Specific permissions for this user.',
        related_query_name='customuser',
    )
