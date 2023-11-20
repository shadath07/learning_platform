from rest_framework import serializers
from courses.models import *
from django.contrib.auth.password_validation import validate_password


class CustomUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = '__all__'
  
        
class TeacherSerializer(serializers.ModelSerializer):
    class Meta:
        model = Teacher
        fields = '__all__'


class StudentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Student
        fields = '__all__'


class CourseSerializer(serializers.ModelSerializer):
    course = serializers.StringRelatedField()
    teacher = serializers.StringRelatedField()
    class Meta:
        model = Course
        fields = '__all__'
    
        
class CourseFormSerializer(serializers.ModelSerializer):
    teacher = serializers.StringRelatedField()
    class Meta:
        model = Course
        fields = ['title', 'description', 'teacher', 'price', 'rating', 'thumbnail']


class ContentSerializer(serializers.ModelSerializer):
    course = serializers.StringRelatedField()
    teacher = serializers.StringRelatedField()
    class Meta:
        model = Content
        fields = '__all__'
        
            
class ContentFormSerializer(serializers.ModelSerializer):
    class Meta:
        model = Content
        fields = ['pdf_file', 'youtube_link']
  
        
class PurchaseSerializer(serializers.ModelSerializer):
    student = serializers.StringRelatedField()
    course = serializers.StringRelatedField()
    teacher = serializers.StringRelatedField()
    class Meta:
        model = Purchase
        fields = ['student','course','purchase_date','teacher']
 
        
class CustomUserRegistrationSerializer(serializers.ModelSerializer):
    email = serializers.EmailField()
    password1 = serializers.CharField(write_only=True, style={'input_type': 'password'})
    password2 = serializers.CharField(write_only=True, style={'input_type': 'password'})
    class Meta:
        model = CustomUser
        fields = ['username', 'email', 'password1', 'password2', 'user_type']
    def validate_password1(self, value):
        validate_password(value)
        return value
    
    def validate(self, data):
        password1 = data.get('password1')
        password2 = data.get('password2')
        if password1 != password2:
            raise serializers.ValidationError("Password and password confirmation do not match.")
        return data
    
    def create(self, validated_data):
        user = CustomUser.objects.create(
            username=validated_data['username'],
            email=validated_data['email'],
            user_type=validated_data['user_type']
        )
        user.set_password(validated_data['password1'])
        user.save()
        return user


class CustomUserLoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True, style={'input_type': 'password'})
    class Meta:
        model = CustomUser
        fields = ['email','password']
     
        
class ResetPasswordSerializer(serializers.Serializer):
    new_password = serializers.CharField(write_only = True, style ={'input_type':'password'})
    confirm_password = serializers.CharField(write_only =True,style={'input_type':'password'})