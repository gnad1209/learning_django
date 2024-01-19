from rest_framework import serializers
from rest_framework_simplejwt.tokens import RefreshToken,TokenError
from .models import CustomUser,BlacklistedToken
from django.contrib.auth.password_validation import validate_password
from rest_framework.validators import UniqueValidator
from django.core.validators import RegexValidator   

class RegisterSerializer(serializers.ModelSerializer):
    address = serializers.CharField(max_length = 255)
    phone_number = serializers.CharField(max_length=10)
    avatar = serializers.ImageField()
    password = serializers.CharField(write_only=True, required=True, validators=[validate_password])
    password2 = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = CustomUser
        fields = ('id','username','email','first_name','last_name' ,'password', 'password2', 'address','phone_number','avatar')

    def validate(self, attrs):
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError(
                {"password": "Password fields didn't match."})

        return attrs

    def create(self, validated_data):
        user = CustomUser.objects.create(
            username=validated_data['username'],
            email=validated_data['email'],
            address=validated_data['address'],
            phone_number=validated_data['phone_number'],
            avatar=validated_data['avatar'],
            first_name=validated_data['first_name'],
            last_name=validated_data['last_name'],
        )

        user.set_password(validated_data['password'])
        user.save()

        return user

#todo
class BlacklistedTokenSerializer(serializers.ModelSerializer):
    class Meta:
        model = BlacklistedToken
        fields = '__all__'


class LogoutSerializers(serializers.Serializer):
    refresh = serializers.CharField()

    default_error_messages = {
        'bad_token': ('Token is invalid or expired')
    }

    def validate(self, attrs):
        self.token = attrs['refresh']
        return attrs

    def save(self, **kwargs):
        try:
            RefreshToken(self.token).blacklist()
        except TokenError:
            self.fail('bad_token')

# class ChangePasswordSerializer(serializers.Serializer):
#     model = CustomUser

#     """
#     Serializer for password change endpoint.
#     """
#     old_password = serializers.CharField(required=True)
#     new_password = serializers.CharField(required=True)