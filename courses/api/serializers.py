from rest_framework import serializers
from courses.models import *


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
    class Meta:
        model = Course
        fields = '__all__'
    
        
class CourseFormSerializer(serializers.ModelSerializer):
    class Meta:
        model = Course
        fields = ['title', 'description', 'teacher', 'price', 'rating']


class ContentSerializer(serializers.ModelSerializer):
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
    # content = serializers.StringRelatedField()
    class Meta:
        model = Purchase
        fields = ['student','course','purchase_date','teacher','content']
 
        
class CustomUserRegistrationSerializer(serializers.ModelSerializer):
    email = serializers.EmailField()
    password1 = serializers.CharField(write_only=True, style={'input_type': 'password'})
    password2 = serializers.CharField(write_only=True, style={'input_type': 'password'})
    class Meta:
        model = CustomUser
        fields = ['username', 'email', 'password1', 'password2', 'user_type']
    def create(self, validated_data):
        password1 = validated_data.pop('password1')
        password2 = validated_data.pop('password2')
        if password1 != password2:
            raise serializers.ValidationError("Password and password confirmation do not match.")
        user = CustomUser(**validated_data)
        user.set_password(password1)
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