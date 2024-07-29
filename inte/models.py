from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin

class UserManager(BaseUserManager):
    def create_user(self, email, name, organization, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, name=name, organization=organization, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, name, organization, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return self.create_user(email, name, organization, password, **extra_fields)

class User(AbstractBaseUser, PermissionsMixin):
    name = models.CharField(max_length=100)
    email = models.EmailField(unique=True)
    organization = models.CharField(max_length=100)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)

    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['name', 'organization']

    def __str__(self):
        return self.email


class Invoice(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    invoice_number = models.CharField(max_length=100)
    purchase_order_number = models.CharField(max_length=100)
    vendor_name = models.CharField(max_length=255)
    code = models.CharField(max_length=255, default='DEFAULT_CODE')  # Use appropriate default if necessary
    msgtxt = models.CharField(max_length=255, default='DEFAULT_MSG')  # Use appropriate default if necessary
    date = models.DateField(auto_now_add=True)
    
    def __str__(self):
        return f"Invoice {self.invoice_number} - {self.code} - {self.msgtxt}"



# OTP model
 
from django.db import models
from django.utils import timezone
from datetime import timedelta
 
class OTP(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    otp = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
 
    def save(self, *args, **kwargs):
        if not self.expires_at:
            self.expires_at = timezone.now() + timedelta(minutes=5)
        super().save(*args, **kwargs)
 
    def is_valid(self):
        return timezone.now() < self.expires_at