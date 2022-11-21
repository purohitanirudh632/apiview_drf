from rest_framework import serializers
from django.contrib.auth.models import User 

class UserAuthSerializer(serializers.ModelSerializer):

    class Meta:
        model = User
        fields = '__all__'
        extra_kwargs = {"password":{"write_only":True}}
    

    def save(self, **kwargs):
        user = User.objects.create_user(**self.validated_data)
        return user