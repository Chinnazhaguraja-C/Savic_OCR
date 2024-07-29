from django import forms

class UploadFileForm(forms.Form):
    myfile = forms.FileField()


from django import forms
from django.contrib.auth import get_user_model
 
User = get_user_model()
 
class ResetPasswordForm(forms.Form):
    email = forms.EmailField(label='Email Address', max_length=100, widget=forms.EmailInput(attrs={'placeholder': 'Email Address'}))
    current_password = forms.CharField(label='Current Password', widget=forms.PasswordInput(attrs={'placeholder': 'Current Password'}))
    new_password = forms.CharField(label='New Password', widget=forms.PasswordInput(attrs={'placeholder': 'New Password'}))
    confirm_password = forms.CharField(label='Confirm Password', widget=forms.PasswordInput(attrs={'placeholder': 'Confirm Password'}))
 
    def clean_email(self):
        email = self.cleaned_data['email']
        try:
            User.objects.get(email=email)
        except User.DoesNotExist:
            raise forms.ValidationError("User does not exist.")
        return email