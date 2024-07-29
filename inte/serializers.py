from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import make_password

User = get_user_model()

class UserSerializer(serializers.ModelSerializer):
    confirm_password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ['name', 'email', 'organization', 'password', 'confirm_password']
        extra_kwargs = {
            'password': {'write_only': True}
        }

    def validate(self, data):
        if data['password'] != data['confirm_password']:
            raise serializers.ValidationError("Passwords do not match.")
        return data

    def create(self, validated_data):
        validated_data['password'] = make_password(validated_data['password'])
        validated_data.pop('confirm_password')
        user = User.objects.create(**validated_data)
        return user


        
        
        
from rest_framework import serializers
from inte.models import User
from .models import Invoice

class InvoiceSerializer(serializers.ModelSerializer):
    user = serializers.PrimaryKeyRelatedField(queryset=User.objects.all())

    class Meta:
        model = Invoice
        fields = [
            'id', 'user', 'invoice_number', 'purchase_order_number', 
            'vendor_name', 'code', 'msgtxt'
        ]


# OTP serializers
 
from rest_framework import serializers
 
class OTPRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()
 
    def validate_email(self, value):
        if not User.objects.filter(email=value).exists():
            raise serializers.ValidationError("User with this email does not exist.")
        return value