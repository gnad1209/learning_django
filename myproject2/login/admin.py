from django.contrib import admin
from .models import CustomUser, BlacklistedToken
# Register your models here.

admin.site.register(CustomUser)
admin.site.register(BlacklistedToken)