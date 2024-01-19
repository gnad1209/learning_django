# Create your models here.
from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils import timezone
from rest_framework.permissions import BasePermission
from django.contrib.auth.models import User
from django.core.validators import RegexValidator

class CustomUser(AbstractUser):
    email = models.EmailField(unique=True)
    address = models.CharField(max_length = 255,blank=True,null=True,)
    phone_number = models.CharField(max_length = 10,blank=True,null=True)
    #test
    avatar = models.ImageField(upload_to='images/', blank=True, null=True)
    REQUIRED_FIELDS = []

    def __str__(self):
        return self.username

    def validate_phone_number(value):
        phone_regex = RegexValidator(
            regex=r'^0[0-9]{9}$',
            message='Số điện thoại phải bắt đầu bằng số 0 và có 10 chữ số.',
        )
        phone_regex(value)

class BlacklistedToken(models.Model): 
    token = models.CharField(max_length=255, unique=True)
    user = models.ForeignKey(CustomUser, related_name="token_user", on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.token
