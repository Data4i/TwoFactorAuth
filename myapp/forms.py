from django import forms
from django.contrib.auth.forms import UserCreationForm
from crispy_forms_gds.helper import FormHelper
from crispy_forms_gds.layout import Field, Layout, Size, Submit
from .models import CustomUser

class CustomUserCreationForm(UserCreationForm):
    phone_number = forms.CharField(max_length=15, required=False, widget=forms.TextInput(attrs={
        'placeholder': 'Phone number',
    }))
    use_sms_2fa = forms.BooleanField(required=False, label='Use SMS for 2FA')
    
    class Meta:
        model = CustomUser
        fields = ('username', 'password1', 'password2', 'email', 'phone_number', 'use_sms_2fa')

    def __init__(self, *args, **kwargs):
        super(CustomUserCreationForm, self).__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.layout = Layout(
            Field('username'),
            Field('password1'),
            Field('password2'),
            Field('email'),
            Field('phone_number'),
            Field('use_sms_2fa', wrapper_class='form-check', legend_size=Size.MEDIUM),
            Submit('submit', 'Signup', css_class='btn btn-primary btn-block')
        )
        self.fields['username'].help_text = ''
        self.fields['password1'].help_text = ''
        self.fields['password2'].help_text = ''
        self.fields['email'].help_text = ''
        

class OTPVerificationForm(forms.Form):
    otp = forms.CharField(max_length=6, required=True)
