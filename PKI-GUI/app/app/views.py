from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect, HttpResponseRedirect
from django.contrib.auth import authenticate, logout
from django.contrib.auth import login as my_custom_login
from django.contrib import messages
from .models import *
from datetime import date
from django.db import IntegrityError
from django.views.decorators.http import require_POST
# Use the API
# from .API_Request.User_All import *
# from .API_Request.Keys_All import *
# from .API_Request.DB_Request import *
# from .API_Request.CSR_Create import *
# from .API_Request.Active_HSM import *
# from .API_Request.Certificate_All import *
# from .API_Request.DownloadFile import *
# from .API_Request.RemoveFile import *
# from .API_Request.CSR_To_HSM import *
# Us the Rabbitmq
from .API_Request.RabbitMQall import *
from django.http import FileResponse
from django.http import HttpResponse,JsonResponse
import os
import tempfile
from django.contrib.auth.models import User
#from .Rules import *
import zipfile
from django.db import models
from .Users_Action import custom_ldap_authenticate, create_ldap_user
from .OTPUsers import *
import json
from django.utils import timezone
import csv
from .Multi_Auth import Mail_numberCreate, Send_SMS
from .IP_Pool_Check import are_all_ips, are_all_ports
import ast
from datetime import datetime, timedelta
from django.contrib.auth.models import Group, Permission
from django.contrib.auth.decorators import user_passes_test
from .PasswordChageSend import Mail_Password_Send, encrypt, decrypt,calculate_minute_difference
from .DashboardCheck import *
from django.db.models import Q
from .CSV_to_Json import get_file_info


# your_app/views.py
TenantName = os.environ.get("NAMESPACE")
def custom_404(request,exception):
    return render(request, '404.html', status=404)

def custom_500(request):
    return render(request, '500.html', status=500)


##### Page Access ####
# views.py
from django.http import HttpResponseForbidden

def user_type_required(user_types):
    def decorator(view_func):
        @login_required
        def wrapper(request, *args, **kwargs):
            user_profile = UserProfile.objects.get(user=request.user)
            print(user_profile.USerType)
            
            if user_profile.USerType in user_types:
                return view_func(request, *args, **kwargs)
            else:
                return render(request, 'Access_Denied.html')
                #return HttpResponseForbidden("You don't have permission to access this page.")
        return wrapper
    return decorator

# SystemGroup'u al veya oluştur
# system_group, created = Group.objects.get_or_create(name='SystemGroup')
# # Tüm izinleri al
# all_permissions = Permission.objects.all()
# # Gruba tüm izinleri ekle
# system_group.permissions.set(all_permissions)
def is_member_of_group(user):
    return user.groups.filter(name='OperatorGroup').exists()

#### Login and Register ####
def login_index(request):
    Tanent_Name = os.environ.get("NAMESPACE")
    if request.user.is_authenticated:
        return redirect('index')
    else:
        if request.method == 'POST':
            
            username = request.POST.get('username')
            password = request.POST.get('password')
            user_type = request.POST.get('user_type')
            if user_type == 'DB':
                try:
                    user_id = User.objects.get(username=username)
                    UserTanent = UserProfile.objects.filter(user=user_id.id).values_list('MultiTenantName', flat=True).first()
                    if TenantName == UserTanent:
                        user = authenticate(request, username=username, password=password)
                    else:
                        messages.error(request, 'User does not belong to this tenant')
                        return redirect('login')
                except:
                    messages.error(request, 'User Not Found')
                    return redirect('login')
                                        
                if user is not None:
                    print(user.id)
                    TwoFactor = UserProfile.objects.get(user_id=user.id)
                    if TwoFactor.TwoFactor == 'Enable':
                        print("Buradaki")
                        request.session['authenticated_user'] = user.id
                        return redirect('verify_2fa_view')
                    elif TwoFactor.TwoFactor == 'Disable':
                        my_custom_login(request, user)
                        UserType = UserProfile.objects.filter(user=request.user.id).values_list('USerType', flat=True).first()
                        MultiTenantName = UserProfile.objects.filter(user=request.user.id).values_list('MultiTenantName', flat=True).first()
                        if UserType == 'Client_User':
                            return redirect('Client_Cert')
                            
                        else:
                            return redirect('index')
                            
                else:
                    return redirect('login_message_return')

            elif user_type == 'Ldap':
                ldap_user = custom_ldap_authenticate(username,password)
                if ldap_user is not None:
                    TwoFactor = UserProfile.objects.get(user=ldap_user.id)
                    if TwoFactor.TwoFactor == 'Enable':
                        request.session['authenticated_user'] = ldap_user.id
                        return redirect('verify_2fa_view')
                    elif TwoFactor.TwoFactor == 'Disable':
                        my_custom_login(request, ldap_user)
                        UserType = UserProfile.objects.filter(user=request.user.id).values_list('USerType', flat=True).first()
                        MultiTenantName = UserProfile.objects.filter(user=request.user.id).values_list('MultiTenantName', flat=True).first()
                        if UserType == 'Client_User':
                            return redirect('Client_Cert')
                            
                        else:
                            return redirect('index')
                            
                else:
                    return redirect('login_message_return')
            elif user_type == 'HSM':
                TokenName = slotlist.objects.all()
                User_All = []
                for Token in TokenName:
                    Check_Result = Check_Token_Slot_Request(Token.TokenName)
                    if Check_Result == 'healthy':
                        PIN_Encrypt = slotlist.objects.filter(TokenName=Token.TokenName).values_list('UserPIN', flat=True).first()
                        Action = "Decrypt"
                        result = Slot_PIN_ENC_DEC(Action,PIN_Encrypt)
                        json_string = json.dumps(result)
                        loaded_data = json.loads(json_string)
                        Token_PIN = loaded_data['Message:']['Decrypt Data: ']
                        Slot_Info = FindID(Token.TokenName)
                        Token_ID = Slot_Info['Message: ']['slot_id']
                        Users = Users_Obje_all(Token_ID,Token_PIN)
                        User_All += Users
                for i in range(len(User_All)):
                    if User_All[i]['UserName'] == username:
                        print(type(User_All[i]))
                        json_user = json.dumps(User_All[i])
                        loaded_user = json.loads(json_user)
                        print(loaded_user['Token_Name'])
                        TokenNames = loaded_user['Token_Name']
                        Slot_ID = loaded_user['Slot_ID']
                        PIN_Encrypt = slotlist.objects.filter(TokenName=TokenNames).values_list('UserPIN', flat=True).first()
                        Action = "Decrypt"
                        result = Slot_PIN_ENC_DEC(Action,PIN_Encrypt)
                        json_string = json.dumps(result)
                        loaded_data = json.loads(json_string)
                        Token_PIN = loaded_data['Message:']['Decrypt Data: ']
                        result = UserVerify_Rabbit(Slot_ID,Token_PIN,username,password)
                        print(result['user Response'])
                        try:
                            user_HSM = User.objects.get(username=username)
                        except:
                            user = User.objects.create_user(username, email='', password='')
                            UserQR = QRCreate(username)
                            json_data = json.dumps(UserQR)
                            parsed_data = json.loads(json_data)
                            Profil_Create = UserProfile.objects.create(user=user, UserType="HSM", TwoFactor="Disable",OTP_Value=parsed_data['user_secret'],QR_Path=parsed_data['IMG_URL'])
                            Profil_Create.save()
                            Sensivity_user = "INFO"
                            Process_user = "Create"
                            Description_user = f'user named {username} was created'
                            hsm_user_create = Logs(Log_Sensitives=Sensivity_user, Log_Process=Process_user, Description=Description_user, created_by=request.user, MultiTenantName=TenantName)
                            hsm_user_create.save()
                            user_HSM = User.objects.get(username=username)
                        if result['user Response'] == 'User Verfty':
                            my_custom_login(request, user_HSM)
                            UserType = UserProfile.objects.filter(user=request.user.id).values_list('USerType', flat=True).first()
                            MultiTenantName = UserProfile.objects.filter(user=request.user.id).values_list('MultiTenantName', flat=True).first()
                            if UserType == 'Client_User':
                                return redirect('Client_Cert')
                            else:
                                return redirect('index')
                                
                        else:
                            return redirect('login_message_return')
                    else:
                        pass
        
        return render(request, 'Login.html',{'Tanent_Name':Tanent_Name})

def login_message_return(request):
    messages.error(request, 'Username OR password is incorrect')
    return redirect('login')

def login(request):
    return redirect('login_index')

def register(request):
    if request.user.is_authenticated:
        return redirect('index')
    else:
        if request.method == 'POST':
            username = request.POST.get('username')
            email = request.POST.get('email')
            FullName = request.POST.get('FullName')
            FirstName = request.POST.get('FirstName')
            LastName = request.POST.get('LastName')
            password1 = request.POST.get('password1')
            password2 = request.POST.get('password2')
            user_type = request.POST.get('user_type')
            phoneNumber = request.POST.get('phoneNumber')
            
            cleaned_phone_number = phoneNumber.replace("-", "")
            UserName = FirstName +" "+LastName
            UserQR = QRCreate(UserName)
            json_data = json.dumps(UserQR)
            parsed_data = json.loads(json_data)
 
            if user_type == 'DB':
                if password1 == password2:
                    user = User.objects.create_user(username=username, first_name=FirstName, last_name=LastName, password=password1, email=email)
                    Profil_Create = UserProfile.objects.create(user=user, UserType="Django", TwoFactor="Disable",OTP_Value=parsed_data['user_secret'],QR_Path=parsed_data['IMG_URL'], telephone_number=cleaned_phone_number, MultiTenantName=TenantName)
                    Profil_Create.save()
                    #login(request, user)
                    messages.success(request, 'DB User created')
                    return redirect('login')
                else:
                    messages.success(request, 'Password not compatible')
                    return render(request, 'register.html')
            elif user_type == 'Ldap':
                if password1 == password2:
                    Full = str(FirstName)+" "+str(LastName)
                    User_Ldap = create_ldap_user(username,str(Full),password1)
                    # if User_Ldap == 'Connection faild':
                    #     messages = "Connection faild"
                    #     return render(request, 'register.html',{'messages':messages})
                    # else:
                    messages.success(request, 'Ldap User created')
                    return redirect('login')
                else:
                    messages.success(request, 'Password not compatible')
                    return render(request, 'register.html')
        else:
            return render(request, 'register.html')

def forgotpassword(request):
    if request.method == 'POST':
        email = request.POST['email']
        try:
            email_user = User.objects.get(email=email)
            plaint_email = email.encode('utf-8')
            E_mail_ENC = encrypt(plaint_email)
            Mail_Password_Send(email,E_mail_ENC)
            messages.success(request, 'Email sent for password update')
            return redirect('login')
        except:
            print("No user found for the entered email")
            messages.success(request, 'No user found for the entered email')
            return redirect('login')
        
    return render(request, 'Forgot_Password.html')

def PasswordChange(request,Email,DataEnc):
    Email_Decrypt = decrypt(Email)
    Date_STR = decrypt(DataEnc) 
    print(Date_STR.decode())
    print(Email_Decrypt.decode())
    Date_Return = calculate_minute_difference(Date_STR.decode())
    if Date_Return:
        if request.method == 'POST':
            password1 = request.POST['password1']
            password2 = request.POST['password2']
            Emil_str = Email_Decrypt.decode()
            if password1 == password2:
                user = User.objects.get(email=Emil_str)
                user.password = password1
                user.save()
            messages.success(request, 'Password changed successfully')
            return redirect('index')
    else:
        messages.success(request, 'URL is invalid')
        return redirect('login')
    return render(request, 'PasswordChanges.html')

def return_index(request):
    return redirect('index')



@login_required
@user_type_required(user_types=['System_User','Operator_User'])
def index(request):
    host_name = request.get_host()
    print(host_name.split(':')[0])
    UserType = UserProfile.objects.filter(user=request.user.id).values_list('USerType', flat=True).first()
    HSM_All_object = hsmpool.objects.filter(created_by=request.user.id, MultiTenantName=TenantName)
    #HSM_All_object = hsmpool.objects.all()
    if request.method == 'POST':
        hsm_pool_name=request.POST['hsm_pool_name']
        hsm_ip_addres = request.POST['hsm_ip_addres']
        hsm_port_addres = request.POST['hsm_port_addres']
        hsm_type = request.POST['hsm_type']
        hsm_ip_array = hsm_ip_addres.split(',')
        hsm_port_array = hsm_port_addres.split(',')
        if len(hsm_ip_array) == len(hsm_port_array):
            if are_all_ips(hsm_ip_array) and are_all_ports(hsm_port_array):
                multifactor_value = MultifactorModel.objects.filter(user_factor=request.user.id).values_list('Pool_create', flat=True).first()
                #multifactor_value = UserProfile.objects.filter(user=request.user).values_list('MulfiFactor', flat=True).first()
                if multifactor_value == 'Disable':
                    try:
                        hsm_pool = hsmpool(HSM_Pool_Name=hsm_pool_name, HSM_IP=hsm_ip_addres, HSM_Port=hsm_port_addres, HSM_Pool_Type=hsm_type)
                        hsm_pool._request = request
                        hsm_pool.save()
                        Sensivity = "INFO"
                        Process = "System"
                        Description = f'HSM Pool named {hsm_pool_name} has been created'
                        HSM_Log = Logs(Log_Sensitives=Sensivity, Log_Process=Process, Description=Description, created_by=request.user, MultiTenantName=TenantName)
                        HSM_Log.save()
                        messages.success(request, 'HSM Pool is create')
                        return redirect('index')
                    except IntegrityError as e:
                        if 'unique constraint' in str(e):
                            print("Error: This record already exists. Try another value.")
                            messages.success(request, 'Error: This record already exists. Try another value.')
                            return redirect('index')
                        else:
                            print("An unexpected error occurred:", e)
                            messages.success(request, f'An unexpected error occurred:{e}.')
                            return redirect('index')

                else:
                    #### Multi Factor 
                    request.session['hsm_pool_name'] = hsm_pool_name
                    request.session['hsm_ip_addres'] = hsm_ip_addres
                    request.session['hsm_port_addres'] = hsm_port_addres
                    request.session['hsm_type'] = hsm_type
                    number = UserProfile.objects.filter(user=request.user).values_list('telephone_number', flat=True).first()
                    sms_number = Send_SMS(number)
                    request.session['sms_number'] = sms_number
                    email = User.objects.filter(pk=request.user.pk).values_list('email', flat=True).first()
                    mail_number = Mail_numberCreate(email)
                    request.session['mail_number'] = mail_number
                    return redirect('Multifactor_index')
            else:
                messages.success(request, 'At least one of the IP addresses provided is incorrect')
                return redirect('index')
        else:
            messages.success(request, 'You entered missing IP address and port information')
            return redirect('index')
    else:
        return render(request, 'index.html', {'HSM_All_object': HSM_All_object, 'UserType':UserType, 'TenantName':TenantName})
@login_required
@user_type_required(user_types=['System_User','Operator_User'])
def Multifactor_index(request):
    UserType = UserProfile.objects.filter(user=request.user.id).values_list('USerType', flat=True).first()
    HSM_All_object = hsmpool.objects.filter(created_by=request.user.id, MultiTenantName=TenantName)
    #HSM_All_object = hsmpool.objects.all()
    multifactor = True
    mail_number = request.session['mail_number']
    sms_number = request.session['sms_number']
    hsm_type = request.session['hsm_type']
    hsm_port_addres = request.session['hsm_port_addres']
    hsm_ip_addres = request.session['hsm_ip_addres']
    hsm_pool_name = request.session['hsm_pool_name']

    if request.method == 'POST':
        sms_name_input = request.POST['sms_name']
        eposta_name_input = request.POST['eposta_name']
        if sms_name_input == sms_number and eposta_name_input == mail_number:
            try:
                hsm_pool = hsmpool(HSM_Pool_Name=hsm_pool_name, HSM_IP=hsm_ip_addres, HSM_Port=hsm_port_addres, HSM_Pool_Type=hsm_type)
                hsm_pool._request = request
                hsm_pool.save()
                Sensivity = "INFO"
                Process = "System"
                Description = f'HSM Pool named {hsm_pool_name} has been created'
                HSM_Log = Logs(Log_Sensitives=Sensivity, Log_Process=Process, Description=Description, created_by=request.user,MultiTenantName=TenantName)
                HSM_Log.save()
                messages.success(request, 'HSM Pool is create')
                return redirect('index')
            except IntegrityError as e:
                if 'unique constraint' in str(e):
                    print("Error: This record already exists. Try another value.")
                    messages.success(request, 'Error: This record already exists. Try another value.')
                    return redirect('index')
                else:
                    print("An unexpected error occurred:", e)
                    messages.success(request, f'An unexpected error occurred:{e}.')
                    return redirect('index')
        else:
            return redirect('index')
    return render(request, 'index.html', {'HSM_All_object': HSM_All_object, 'multifactor': multifactor, 'UserType':UserType, 'TenantName':TenantName})



@login_required
@user_type_required(user_types=['System_User','Operator_User'])
def Pool_delete(request, id):
    UserType = UserProfile.objects.filter(user=request.user.id).values_list('USerType', flat=True).first()
    Object_single = hsmpool.objects.get(id=id)
    multifactor_value = MultifactorModel.objects.filter(user_factor=request.user.id).values_list('Pool_delete', flat=True).first()
    #multifactor_value = UserProfile.objects.filter(user=request.user).values_list('MulfiFactor', flat=True).first()
    if multifactor_value == 'Disable':
        Object_single.delete()
        Sensivity = "WARNING"
        Process = "Delete"
        HSM_pool_name = Object_single.HSM_Pool_Name
        Description = f'Deleted HSM Pool named {HSM_pool_name}'
        HSM_Log = Logs(Log_Sensitives=Sensivity, Log_Process=Process, Description=Description, created_by=request.user,MultiTenantName=TenantName)
        HSM_Log.save()
        messages.success(request, 'HSM Pool is delete')
        return redirect('index')
    else:
        request.session['Obje_id'] = id
        number = UserProfile.objects.filter(user=request.user).values_list('telephone_number', flat=True).first()
        sms_number = Send_SMS(number)
        request.session['sms_number'] = sms_number
        email = User.objects.filter(pk=request.user.pk).values_list('email', flat=True).first()
        mail_number = Mail_numberCreate(email)
        request.session['mail_number'] = mail_number
        return redirect('Multifactor_Pool_delete')

@login_required
@user_type_required(user_types=['System_User','Operator_User'])
def Multifactor_Pool_delete(request):
    multifactor = True
    UserType = UserProfile.objects.filter(user=request.user.id).values_list('USerType', flat=True).first()
    HSM_All_object = hsmpool.objects.filter(created_by=request.user.id, MultiTenantName=TenantName)
    #HSM_All_object = hsmpool.objects.all()
    id = request.session['Obje_id']
    sms_number = request.session['sms_number']
    mail_number = request.session['mail_number']
    Object_single = hsmpool.objects.get(id=id)
    if request.method == 'POST':
        sms_name_input = request.POST['sms_name']
        eposta_name_input = request.POST['eposta_name']
        if sms_name_input == sms_number and eposta_name_input == mail_number:
            Object_single.delete()
            Sensivity = "WARNING"
            Process = "Delete"
            HSM_pool_name = Object_single.HSM_Pool_Name
            Description = f'Deleted HSM Pool named {HSM_pool_name}'
            HSM_Log = Logs(Log_Sensitives=Sensivity, Log_Process=Process, Description=Description, created_by=request.user,MultiTenantName=TenantName)
            HSM_Log.save()
            messages.success(request, 'HSM Pool is delete')
            return redirect('index')
        else:
            return redirect('index')

    return render(request, 'index.html', {'HSM_All_object': HSM_All_object, 'multifactor':multifactor, 'UserType':UserType, 'TenantName':TenantName})
@login_required
@user_type_required(user_types=['System_User','Operator_User'])
def Pool_Active(request, hsm_pool_name):
    multifactor_value = MultifactorModel.objects.filter(user_factor=request.user.id).values_list('Pool_Active', flat=True).first()
    #multifactor_value = UserProfile.objects.filter(user=request.user).values_list('MulfiFactor', flat=True).first()
    if multifactor_value == 'Disable':
        try:
            Object_make_passive = hsmpool.objects.get(HSM_Status="active")
            Sensivity = "INFO"
            Process = "System"
            HSM_name = Object_make_passive.HSM_Pool_Name
            Description = f'HSM Pool named {HSM_name} put in inactive mode'
            HSM_Log = Logs(Log_Sensitives=Sensivity, Log_Process=Process, Description=Description, created_by=request.user,MultiTenantName=TenantName)
            Object_make_passive.HSM_Status = "passive"
            

            Object_make_active = hsmpool.objects.get(HSM_Pool_Name=hsm_pool_name)
            Object_make_active.HSM_Status = "active"
            Sensivity2 = "INFO"
            Process2 = "System"
            HSM_name2 = Object_make_active.HSM_Pool_Name
            Description2 = f'HSM Pool named {HSM_name2} put into active mode'
            HSM_Log2 = Logs(Log_Sensitives=Sensivity2, Log_Process=Process2, Description=Description2, created_by=request.user,MultiTenantName=TenantName)
            IP_HSM = Object_make_active.HSM_IP
            PORT_HSM = Object_make_active.HSM_Port
            result = Active_HSM_Request(IP_HSM,PORT_HSM)
            print(result['message'])
            if 'incorrect' in result['message']:
                Object_make_passive.HSM_Status = "active"
                Object_make_active.HSM_Status = "passive"
            else:
                Object_make_passive.HSM_Status = "passive"
                Object_make_active.HSM_Status = "active"
            Object_make_passive.save()
            HSM_Log.save()
            Object_make_active.save()
            HSM_Log2.save()
            messages.success(request, result['message'])
        except:
            Object_make_active = hsmpool.objects.get(HSM_Pool_Name=hsm_pool_name)
            Object_make_active.HSM_Status = "active"
            IP_HSM = Object_make_active.HSM_IP
            PORT_HSM = Object_make_active.HSM_Port
            result = Active_HSM_Request(IP_HSM,PORT_HSM)
            print(result)
            Sensivity3 = "INFO"
            Process3 = "System"
            HSM_name3 = Object_make_active.HSM_Pool_Name
            Description3 = f'HSM Pool named {HSM_name3} put into active mode'
            HSM_Log3 = Logs(Log_Sensitives=Sensivity3, Log_Process=Process3, Description=Description3, created_by=request.user,MultiTenantName=TenantName)
            HSM_Log3.save()
            Object_make_active.save()
            messages.success(request, result['message'])
        return redirect('index')
    else:
        request.session['hsm_pool_name'] = hsm_pool_name
        number = UserProfile.objects.filter(user=request.user).values_list('telephone_number', flat=True).first()
        sms_number = Send_SMS(number)
        request.session['sms_number'] = sms_number
        email = User.objects.filter(pk=request.user.pk).values_list('email', flat=True).first()
        mail_number = Mail_numberCreate(email)
        request.session['mail_number'] = mail_number
        return redirect('Multifactor_Pool_Active')

@login_required
@user_type_required(user_types=['System_User','Operator_User'])
def Multifactor_Pool_Active(request):
    multifactor = True
   # HSM_All_object = hsmpool.objects.all()
    HSM_All_object = hsmpool.objects.filter(created_by=request.user.id)
    UserType = UserProfile.objects.filter(user=request.user.id).values_list('USerType', flat=True).first()
    sms_number = request.session['sms_number']
    mail_number = request.session['mail_number']
    hsm_pool_name = request.session['hsm_pool_name']
    if request.method == 'POST':
        sms_name_input = request.POST['sms_name']
        eposta_name_input = request.POST['eposta_name']
        if sms_name_input == sms_number and eposta_name_input == mail_number:
            try:
                Object_make_passive = hsmpool.objects.get(HSM_Status="active")
                Sensivity = "INFO"
                Process = "System"
                HSM_name = Object_make_passive.HSM_Pool_Name
                Description = f'HSM Pool named {HSM_name} put in inactive mode'
                HSM_Log = Logs(Log_Sensitives=Sensivity, Log_Process=Process, Description=Description, created_by=request.user,MultiTenantName=TenantName)
                Object_make_passive.HSM_Status = "passive"
                Object_make_passive.save()
                HSM_Log.save()

                Object_make_active = hsmpool.objects.get(HSM_Pool_Name=hsm_pool_name)
                Object_make_active.HSM_Status = "active"
                Sensivity2 = "INFO"
                Process2 = "System"
                HSM_name2 = Object_make_active.HSM_Pool_Name
                Description2 = f'HSM Pool named {HSM_name2} put into active mode'
                HSM_Log2 = Logs(Log_Sensitives=Sensivity2, Log_Process=Process2, Description=Description2, created_by=request.user,MultiTenantName=TenantName)
                IP_HSM = Object_make_active.HSM_IP
                PORT_HSM = Object_make_active.HSM_Port
                result = Active_HSM_Request(IP_HSM,PORT_HSM)
                Object_make_active.save()
                HSM_Log2.save()
                messages.success(request, result['message'])
            except:
                Object_make_active = hsmpool.objects.get(HSM_Pool_Name=hsm_pool_name)
                Object_make_active.HSM_Status = "active"
                IP_HSM = Object_make_active.HSM_IP
                PORT_HSM = Object_make_active.HSM_Port
                result = Active_HSM_Request(IP_HSM,PORT_HSM)
                Sensivity3 = "INFO"
                Process3 = "System"
                HSM_name3 = Object_make_active.HSM_Pool_Name
                Description3 = f'HSM Pool named {HSM_name3} put into active mode'
                HSM_Log3 = Logs(Log_Sensitives=Sensivity3, Log_Process=Process3, Description=Description3, created_by=request.user,MultiTenantName=TenantName)
                HSM_Log3.save()
                Object_make_active.save()
                messages.success(request, result['message'])
        return redirect('index')
    return render(request, 'index.html', {'HSM_All_object': HSM_All_object, 'multifactor':multifactor, 'UserType':UserType, 'TenantName':TenantName})
@login_required
@user_type_required(user_types=['System_User','Operator_User'])
def hsm_pool_update(request, id):
    UserType = UserProfile.objects.filter(user=request.user.id).values_list('USerType', flat=True).first()
    if request.method == 'POST':
        # POST verilerini işleyin
        hsm_pool_name = request.POST['hsm_pool_name']
        hsm_ip_addres = request.POST['hsm_ip_addres']
        hsm_port_addres = request.POST['hsm_port_addres']
        hsm_type = request.POST['hsm_type']
        multifactor_value = MultifactorModel.objects.filter(user_factor=request.user.id).values_list('Pool_Upload', flat=True).first()
        #multifactor_value = UserProfile.objects.filter(user=request.user).values_list('MulfiFactor', flat=True).first()
        if multifactor_value == 'Disable':
            obj = hsmpool.objects.get(id=id)
            obj.HSM_Pool_Name = hsm_pool_name
            obj.HSM_IP = hsm_ip_addres
            obj.HSM_Port = hsm_port_addres
            obj.HSM_Pool_Type = hsm_type
            obj.save()
            Sensivity4 = "INFO"
            Process4 = "Upload"
            HSM_name4 = obj.HSM_Pool_Name
            Description4 = f'HSM Pool named {HSM_name4} has been updated'
            HSM_Log4 = Logs(Log_Sensitives=Sensivity4, Log_Process=Process4, Description=Description4, created_by=request.user,MultiTenantName=TenantName)
            HSM_Log4.save()
            messages.success(request, 'HSM Pool is update')
            return redirect('index')
        else:
            ### MultiFactor 
            request.session['hsm_pool_name'] = hsm_pool_name
            request.session['hsm_ip_addres'] = hsm_ip_addres
            request.session['hsm_port_addres'] = hsm_port_addres
            request.session['hsm_type'] = hsm_type
            request.session['id'] = id
            number = UserProfile.objects.filter(user=request.user).values_list('telephone_number', flat=True).first()
            sms_number = Send_SMS(number)
            request.session['sms_number'] = sms_number
            email = User.objects.filter(pk=request.user.pk).values_list('email', flat=True).first()
            mail_number = Mail_numberCreate(email)
            request.session['mail_number'] = mail_number
            return redirect('Multifactor_hsm_pool_update')
    return render(request, 'index.html',{'UserType':UserType, 'TenantName':TenantName})

@login_required
@user_type_required(user_types=['System_User','Operator_User'])
def Multifactor_hsm_pool_update(request):
    UserType = UserProfile.objects.filter(user=request.user.id).values_list('USerType', flat=True).first()
    multifactor = True
    HSM_All_object = hsmpool.objects.filter(created_by=request.user.id, MultiTenantName=TenantName)
   # HSM_All_object = hsmpool.objects.all()
    hsm_pool_name = request.session['hsm_pool_name']
    hsm_ip_addres = request.session['hsm_ip_addres']
    hsm_port_addres = request.session['hsm_port_addres']
    hsm_type = request.session['hsm_type']
    id = request.session['id']
    sms_number = request.session['sms_number']
    mail_number = request.session['mail_number']
    if request.method == 'POST':
        sms_name_input = request.POST['sms_name']
        eposta_name_input = request.POST['eposta_name']
        if sms_name_input == sms_number and eposta_name_input == mail_number:
            obj = hsmpool.objects.get(id=id)
            obj.HSM_Pool_Name = hsm_pool_name
            obj.HSM_IP = hsm_ip_addres
            obj.HSM_Port = hsm_port_addres
            obj.HSM_Pool_Type = hsm_type
            obj.save()
            Sensivity4 = "INFO"
            Process4 = "Upload"
            HSM_name4 = obj.HSM_Pool_Name
            Description4 = f'HSM Pool named {HSM_name4} has been updated'
            HSM_Log4 = Logs(Log_Sensitives=Sensivity4, Log_Process=Process4, Description=Description4, created_by=request.user, MultiTenantName=TenantName)
            HSM_Log4.save()
            messages.success(request, 'HSM Pool is update')
            return redirect('index')
        else:
            return redirect('index')
    return render(request, 'index.html', {'HSM_All_object': HSM_All_object, 'multifactor':multifactor, 'UserType':UserType, 'TenantName':TenantName})

def logout(request):
    logout(request)
    return redirect('login_index')


@login_required
@user_type_required(user_types=['System_User','Operator_User'])
def Slot_List(request):
    UserType = UserProfile.objects.filter(user=request.user.id).values_list('USerType', flat=True).first()
    HSM_Name = hsmpool.objects.filter(MultiTenantName=TenantName, HSM_Status='active')
    HSM_All_object = slotlist.objects.filter(MultiTenantName=TenantName)
    result_Token = HSM_Tokens_Request()
    Token_Name = result_Token['message']
    
    if request.method == 'POST':
        multifactor_value = MultifactorModel.objects.filter(user_factor=request.user.id).values_list('Slot_List', flat=True).first()
        try:
            pool_name = request.POST['pool_name']
            hsm_slot_name = request.POST['hsm_slot_name']
            hsm_slot_pin = request.POST['hsm_slot_pin']
        except:
            pool_name = request.POST['pool_name']
            Token_Label = request.POST['Token_Label']
            ho_pin = request.POST['ho_pin']
            ha_pin = request.POST['ha_pin']
            SO_PIN = request.POST['SO_PIN']
            User_PIN = request.POST['User_PIN']
            if multifactor_value == 'Disable':
                result = Token_Create(ho_pin,ha_pin,Token_Label,SO_PIN,User_PIN)
                hsmpool_instance = hsmpool.objects.get(HSM_Pool_Name=pool_name)
                print(result)
                if result == 'Token is created':
                    Action = "Encrypt"
                    result = Slot_PIN_ENC_DEC(Action,User_PIN)
                    json_string = json.dumps(result)
                    loaded_data = json.loads(json_string)
                    try:
                        Encrypted_PIN = loaded_data['Message:']['Encrypt Data: ']
                    except:
                        print("PIN Encryption Faild")
                        messages.success(request, 'PIN Encryption Faild')
                        return redirect('Slot_List')
                    print(Encrypted_PIN)
                    slotlist_obje = slotlist(HSM_Pool_Name=hsmpool_instance,TokenName=Token_Label,UserPIN=Encrypted_PIN)
                    slotlist_obje._request = request
                    slotlist_obje.save()
                    Sensivity_Slot = "INFO"
                    Process_Slot = "Create"
                    str_Token_Label = str(Token_Label)
                    Description_Slot = f'slot named'+ str_Token_Label +'has been created'
                    HSM_Slot_Create = Logs(Log_Sensitives=Sensivity_Slot, Log_Process=Process_Slot, Description=Description_Slot, created_by=request.user, MultiTenantName=TenantName)
                    HSM_Slot_Create.save()
                    return redirect('Slot_List')
                    #     try:

                    #         slotlist_obje = slotlist(HSM_Pool_Name=hsmpool_instance,TokenName=hsm_slot_name,UserPIN=Encrypted_PIN)
                    #         slotlist_obje._request = request
                    #         slotlist_obje.save()

                    #         Sensivity_Slot = "INFO"
                    #         Process_Slot = "Create"
                    #         Description_Slot = f'slot named {hsm_slot_name} has been created'
                    #         HSM_Slot_Create = Logs(Log_Sensitives=Sensivity_Slot, Log_Process=Process_Slot, Description=Description_Slot, created_by=request.user, MultiTenantName=TenantName)
                    #         HSM_Slot_Create.save()
                    #         return redirect('Slot_List')
                    #     except IntegrityError as e:
                    #         if 'unique constraint' in str(e):
                    #             print("Error: This record already exists. Try another value.")
                    #             messages.success(request, 'Error: This record already exists. Try another value.')
                    #             return redirect('Slot_List')
                    #         else:
                    #             print("An unexpected error occurred:", e)
                    #             messages.success(request, f'An unexpected error occurred:{e}.')
                    #             return redirect('Slot_List')
                        
                    # except:
                    #     messages.success(request, 'Slot Identification failed.')
                    #     print("işlem basarisiz")
                    #     return redirect('Slot_List')
                    
                else:
                    Message_Error = "Token is not created"
                    messages.success(request, Message_Error)
                    return redirect('Slot_List')
            else:
                request.session['pool_name'] = pool_name
                request.session['Token_Label'] = Token_Label
                request.session['ho_pin'] = ho_pin
                request.session['ha_pin'] = ha_pin
                request.session['SO_PIN'] = SO_PIN
                request.session['User_PIN'] = User_PIN
                number = UserProfile.objects.filter(user=request.user).values_list('telephone_number', flat=True).first()
                sms_number = Send_SMS(number)
                request.session['sms_number'] = sms_number
                email = User.objects.filter(pk=request.user.pk).values_list('email', flat=True).first()
                mail_number = Mail_numberCreate(email)
                request.session['mail_number'] = mail_number
                return redirect('Multifactor_Token_Create_New')
        hsmpool_instance = hsmpool.objects.get(HSM_Pool_Name=pool_name)
        Action = "Encrypt"
        result = Slot_PIN_ENC_DEC(Action,hsm_slot_pin)
        json_string = json.dumps(result)
        loaded_data = json.loads(json_string)
        print(loaded_data)
        try:
            Encrypted_PIN = loaded_data['Message:']['Encrypt Data: ']
        except:
            messages.success(request, 'Slot Identification failed.')
            print("işlem basarisiz")
            return redirect('Slot_List')
        
        #multifactor_value = UserProfile.objects.filter(user=request.user).values_list('MulfiFactor', flat=True).first()
        if multifactor_value == 'Disable':
            try:

                slotlist_obje = slotlist(HSM_Pool_Name=hsmpool_instance,TokenName=hsm_slot_name,UserPIN=Encrypted_PIN)
                slotlist_obje._request = request
                slotlist_obje.save()

                Sensivity_Slot = "INFO"
                Process_Slot = "Create"
                Description_Slot = f'slot named {hsm_slot_name} has been created'
                HSM_Slot_Create = Logs(Log_Sensitives=Sensivity_Slot, Log_Process=Process_Slot, Description=Description_Slot, created_by=request.user, MultiTenantName=TenantName)
                HSM_Slot_Create.save()
                return redirect('Slot_List')
            except IntegrityError as e:
                if 'unique constraint' in str(e):
                    print("Error: This record already exists. Try another value.")
                    messages.success(request, 'Error: This record already exists. Try another value.')
                    return redirect('Slot_List')
                else:
                    print("An unexpected error occurred:", e)
                    messages.success(request, f'An unexpected error occurred:{e}.')
                    return redirect('Slot_List')

        else:
            request.session['pool_name'] = pool_name
            request.session['hsm_slot_name'] = hsm_slot_name
            request.session['Encrypted_PIN'] = Encrypted_PIN
            number = UserProfile.objects.filter(user=request.user).values_list('telephone_number', flat=True).first()
            sms_number = Send_SMS(number)
            request.session['sms_number'] = sms_number
            email = User.objects.filter(pk=request.user.pk).values_list('email', flat=True).first()
            mail_number = Mail_numberCreate(email)
            request.session['mail_number'] = mail_number
            return redirect('Multifactor_Slot_List')
    else:
        return render(request,'Slot_List.html', {'HSM_Name':HSM_Name, 'HSM_All_object': HSM_All_object, 'UserType':UserType, 'TenantName':TenantName, 'Token_Name':Token_Name})

@login_required
@user_type_required(user_types=['System_User','Operator_User'])
def Multifactor_Token_Create_New(request):
    UserType = UserProfile.objects.filter(user=request.user.id).values_list('USerType', flat=True).first()
    multifactor = True
    HSM_Name = hsmpool.objects.filter(MultiTenantName=TenantName)
    HSM_All_object = slotlist.objects.filter(MultiTenantName=TenantName)
    pool_name = request.session['pool_name']
    Token_Label = request.session['Token_Label']
    ho_pin = request.session['ho_pin']
    ha_pin = request.session['ha_pin']
    SO_PIN = request.session['SO_PIN']
    User_PIN = request.session['User_PIN']
    sms_number = request.session['sms_number']
    mail_number = request.session['mail_number']
    if request.method == 'POST':
        sms_name_input = request.POST['sms_name']
        eposta_name_input = request.POST['eposta_name']
        if sms_name_input == sms_number and eposta_name_input == mail_number:
            result = Token_Create(ho_pin,ha_pin,Token_Label,SO_PIN,User_PIN)
            hsmpool_instance = hsmpool.objects.get(HSM_Pool_Name=pool_name)
            print(result)
            if result == 'Token is created':
                Action = "Encrypt"
                result = Slot_PIN_ENC_DEC(Action,User_PIN)
                json_string = json.dumps(result)
                loaded_data = json.loads(json_string)
                try:
                    Encrypted_PIN = loaded_data['Message:']['Encrypt Data: ']
                except:
                    print("PIN Encryption Faild")
                    messages.success(request, 'PIN Encryption Faild')
                    return redirect('Slot_List')
                print(Encrypted_PIN)
                slotlist_obje = slotlist(HSM_Pool_Name=hsmpool_instance,TokenName=Token_Label,UserPIN=Encrypted_PIN)
                slotlist_obje._request = request
                slotlist_obje.save()
                Sensivity_Slot = "INFO"
                Process_Slot = "Create"
                str_Token_Label = str(Token_Label)
                Description_Slot = f'slot named'+ str_Token_Label +'has been created'
                HSM_Slot_Create = Logs(Log_Sensitives=Sensivity_Slot, Log_Process=Process_Slot, Description=Description_Slot, created_by=request.user, MultiTenantName=TenantName)
                HSM_Slot_Create.save()
                return redirect('Slot_List')
                #     try:

                    #         slotlist_obje = slotlist(HSM_Pool_Name=hsmpool_instance,TokenName=hsm_slot_name,UserPIN=Encrypted_PIN)
                    #         slotlist_obje._request = request
                    #         slotlist_obje.save()

                    #         Sensivity_Slot = "INFO"
                    #         Process_Slot = "Create"
                    #         Description_Slot = f'slot named {hsm_slot_name} has been created'
                    #         HSM_Slot_Create = Logs(Log_Sensitives=Sensivity_Slot, Log_Process=Process_Slot, Description=Description_Slot, created_by=request.user, MultiTenantName=TenantName)
                    #         HSM_Slot_Create.save()
                    #         return redirect('Slot_List')
                    #     except IntegrityError as e:
                    #         if 'unique constraint' in str(e):
                    #             print("Error: This record already exists. Try another value.")
                    #             messages.success(request, 'Error: This record already exists. Try another value.')
                    #             return redirect('Slot_List')
                    #         else:
                    #             print("An unexpected error occurred:", e)
                    #             messages.success(request, f'An unexpected error occurred:{e}.')
                    #             return redirect('Slot_List')
                        
                    # except:
                    #     messages.success(request, 'Slot Identification failed.')
                    #     print("işlem basarisiz")
                    #     return redirect('Slot_List')
                    
            else:
                Message_Error = "Token is not created"
                messages.success(request, Message_Error)
                return redirect('Slot_List')

@login_required
@user_type_required(user_types=['System_User','Operator_User'])
def Multifactor_Slot_List(request):
    UserType = UserProfile.objects.filter(user=request.user.id).values_list('USerType', flat=True).first()
    multifactor = True
    HSM_Name = hsmpool.objects.filter(MultiTenantName=TenantName)
    HSM_All_object = slotlist.objects.filter(MultiTenantName=TenantName)
    pool_name = request.session['pool_name']
    hsm_slot_name = request.session['hsm_slot_name']
    Encrypted_PIN = request.session['Encrypted_PIN']
    mail_number = request.session['mail_number']
    sms_number = request.session['sms_number']
    if request.method == 'POST':
        sms_name_input = request.POST['sms_name']
        eposta_name_input = request.POST['eposta_name']
        if sms_name_input == sms_number and eposta_name_input == mail_number:
            try:
                hsmpool_instance = hsmpool.objects.get(HSM_Pool_Name=pool_name)
                slotlist_obje = slotlist(HSM_Pool_Name=hsmpool_instance,TokenName=hsm_slot_name,UserPIN=Encrypted_PIN)
                slotlist_obje.save()
                Sensivity_Slot = "INFO"
                Process_Slot = "Create"
                Description_Slot = f'slot named {hsm_slot_name} has been created'
                HSM_Slot_Create = Logs(Log_Sensitives=Sensivity_Slot, Log_Process=Process_Slot, Description=Description_Slot, created_by=request.user, MultiTenantName=TenantName)
                HSM_Slot_Create.save()
                return redirect('Slot_List')
            except IntegrityError as e:
                if 'unique constraint' in str(e):
                    print("Error: This record already exists. Try another value.")
                    messages.success(request, 'Error: This record already exists. Try another value.')
                    return redirect('Slot_List')
                else:
                    print("An unexpected error occurred:", e)
                    messages.success(request, f'An unexpected error occurred:{e}.')
                    return redirect('Slot_List')
        else:
            return redirect('Slot_List')
    return render(request,'Slot_List.html', {'HSM_Name':HSM_Name, 'HSM_All_object': HSM_All_object, 'multifactor': multifactor, 'UserType':UserType, 'TenantName':TenantName})

@login_required
@user_type_required(user_types=['System_User','Operator_User'])
def hsm_slot_update(request, id):
    UserType = UserProfile.objects.filter(user=request.user.id).values_list('USerType', flat=True).first()
    if request.method == 'POST':
        # POST verilerini işleyin
        hsm_slot_name = request.POST['hsm_slot_name']
        hsm_slot_pin = request.POST['hsm_slot_pin']
        Action = "Encrypt"
        result = Slot_PIN_ENC_DEC(Action,hsm_slot_pin)
        json_string = json.dumps(result)
        loaded_data = json.loads(json_string)
        Encrypted_PIN = loaded_data['Message:']['Encrypt Data: ']

        multifactor_value = MultifactorModel.objects.filter(user_factor=request.user.id).values_list('hsm_slot_update', flat=True).first()
        #multifactor_value = UserProfile.objects.filter(user=request.user).values_list('MulfiFactor', flat=True).first()
        if multifactor_value == 'Disable':
            object = slotlist.objects.get(id=id)       
            object.TokenName = hsm_slot_name
            object.UserPIN = Encrypted_PIN
            Sensivity_Slot_upload = "INFO"
            Process_Slot_upload = "Upload"
            Slot_Name_upload = object.TokenName
            Description_Slot_Upload = f'Slot named {Slot_Name_upload} has been uploaded'
            HSM_Slot_Create = Logs(Log_Sensitives=Sensivity_Slot_upload, Log_Process=Process_Slot_upload, Description=Description_Slot_Upload, created_by=request.user, MultiTenantName=TenantName)
            HSM_Slot_Create.save()
            object.save()
            return redirect('Slot_List')
        else:
            #### Multi Factor 
            request.session['hsm_slot_name'] = hsm_slot_name
            request.session['Encrypted_PIN'] = Encrypted_PIN
            request.session['Slot_ID'] = id
            number = UserProfile.objects.filter(user=request.user).values_list('telephone_number', flat=True).first()
            sms_number = Send_SMS(number)
            request.session['sms_number'] = sms_number
            email = User.objects.filter(pk=request.user.pk).values_list('email', flat=True).first()
            mail_number = Mail_numberCreate(email)
            request.session['mail_number'] = mail_number
            return redirect('Multifactor_hsm_slot_update')
    return render(request, 'Slot_List.html',{'UserType':UserType, 'TenantName':TenantName})

@login_required
@user_type_required(user_types=['System_User','Operator_User'])
def Multifactor_hsm_slot_update(request):
    UserType = UserProfile.objects.filter(user=request.user.id).values_list('USerType', flat=True).first()
    multifactor = True
    HSM_Name = hsmpool.objects.filter(MultiTenantName=TenantName)
    HSM_All_object = slotlist.objects.filter(MultiTenantName=TenantName)
    hsm_slot_name = request.session['hsm_slot_name']
    Encrypted_PIN = request.session['Encrypted_PIN']
    id = request.session['Slot_ID']
    sms_number = request.session['sms_number']
    mail_number = request.session['mail_number']
    if request.method == 'POST':
        sms_name_input = request.POST['sms_name']
        eposta_name_input = request.POST['eposta_name']
        if sms_name_input == sms_number and eposta_name_input == mail_number:
            object = slotlist.objects.get(id=id)       
            object.TokenName = hsm_slot_name
            object.UserPIN = Encrypted_PIN
            Sensivity_Slot_upload = "INFO"
            Process_Slot_upload = "Upload"
            Slot_Name_upload = object.TokenName
            Description_Slot_Upload = f'Slot named {Slot_Name_upload} has been uploaded'
            HSM_Slot_Create = Logs(Log_Sensitives=Sensivity_Slot_upload, Log_Process=Process_Slot_upload, Description=Description_Slot_Upload, created_by=request.user, MultiTenantName=TenantName)
            HSM_Slot_Create.save()
            object.save()
            return redirect('Slot_List')
        else:
            return redirect('Slot_List')
    return render(request,'Slot_List.html', {'HSM_Name':HSM_Name, 'HSM_All_object': HSM_All_object, 'multifactor':multifactor, 'UserType':UserType, 'TenantName':TenantName})

@login_required
@user_type_required(user_types=['System_User','Operator_User'])
def Slot_delete(request, id):
    Object_single = slotlist.objects.get(id=id)
    multifactor_value = MultifactorModel.objects.filter(user_factor=request.user.id).values_list('Slot_delete', flat=True).first()
    #multifactor_value = UserProfile.objects.filter(user=request.user).values_list('MulfiFactor', flat=True).first()
    if multifactor_value == 'Disable':
        Sensivity_Slot_delete = "WARNING"
        Process_Slot_delete = "Delete"
        Slot_Name_delete = Object_single.TokenName
        Description_Slot_delete = f'slot named {Slot_Name_delete} deleted'
        HSM_Slot_delete = Logs(Log_Sensitives=Sensivity_Slot_delete, Log_Process=Process_Slot_delete, Description=Description_Slot_delete, created_by=request.user, MultiTenantName=TenantName)
        HSM_Slot_delete.save()
        Object_single.delete()
        return redirect('Slot_List')
    else:
        request.session['id'] = id
        number = UserProfile.objects.filter(user=request.user).values_list('telephone_number', flat=True).first()
        sms_number = Send_SMS(number)
        request.session['sms_number'] = sms_number
        email = User.objects.filter(pk=request.user.pk).values_list('email', flat=True).first()
        mail_number = Mail_numberCreate(email)
        request.session['mail_number'] = mail_number
        return redirect('Multifactor_Slot_delete')

@login_required
@user_type_required(user_types=['System_User','Operator_User'])
def Multifactor_Slot_delete(request):
    UserType = UserProfile.objects.filter(user=request.user.id).values_list('USerType', flat=True).first()
    multifactor = True
    HSM_Name = hsmpool.objects.filter(MultiTenantName=TenantName)
    HSM_All_object = slotlist.objects.filter(MultiTenantName=TenantName)
    id = request.session['id']
    sms_number = request.session['sms_number']
    mail_number = request.session['mail_number']
    Object_single = slotlist.objects.get(id=id)
    if request.method == 'POST':
        sms_name_input = request.POST['sms_name']
        eposta_name_input = request.POST['eposta_name']
        if sms_name_input == sms_number and eposta_name_input == mail_number:
            Sensivity_Slot_delete = "WARNING"
            Process_Slot_delete = "Delete"
            Slot_Name_delete = Object_single.TokenName
            Description_Slot_delete = f'slot named {Slot_Name_delete} deleted'
            HSM_Slot_delete = Logs(Log_Sensitives=Sensivity_Slot_delete, Log_Process=Process_Slot_delete, Description=Description_Slot_delete, created_by=request.user, MultiTenantName=TenantName)
            HSM_Slot_delete.save()
            Object_single.delete()
            return redirect('Slot_List')
        else:
            return redirect('Slot_List')
    return render(request,'Slot_List.html', {'HSM_Name':HSM_Name, 'HSM_All_object': HSM_All_object, 'multifactor':multifactor, 'UserType':UserType, 'TenantName':TenantName})


@login_required
@user_type_required(user_types=['System_User','Operator_User'])
def Certificates_List(request):
    UserType = UserProfile.objects.filter(user=request.user.id).values_list('USerType', flat=True).first()
    HSM_All_object = slotlist.objects.filter(MultiTenantName=TenantName)
    obje = certificates.objects.filter(created_by=request.user.id, MultiTenantName=TenantName)
    if request.method == 'POST':
        Token_Name = request.POST['Token_Name']
        CertificateName = request.POST['CertificateName']
        CommonName = request.POST['CommonName']
        OrganizationName = request.POST['OrganizationName']
        CountryName = request.POST['CountryName']
        KeyName = request.POST['KeyName']
        KeyBIT = request.POST['KeyBIT']
        PIN_Encrypt = slotlist.objects.filter(TokenName=Token_Name).values_list('UserPIN', flat=True).first()
        Action = "Decrypt"
        result = Slot_PIN_ENC_DEC(Action,PIN_Encrypt)
        json_string = json.dumps(result)
        loaded_data = json.loads(json_string)
        Token_PIN = loaded_data['Message:']['Decrypt Data: ']
        Slot_Info = FindID(Token_Name)
        Token_ID = Slot_Info['Message: ']['slot_id']
        ### Sessions ###
        Token_ID =  request.session['Token_ID']
        Token_PIN =  request.session['Token_PIN']
        KeyName =  request.session['KeyName']
        KeyBIT =  request.session['KeyBIT']


        Key_Result = RSA_Create_Request(Token_ID,Token_PIN,KeyName, KeyBIT)
        if KeyName in Key_Result['message:']:
            ### Key Create #####
            Sensivity_key_create = "INFO"
            Process_key_create = "Create"
            Description_key_create = f'Created key named {KeyName}'
            HSM_key_create  = Logs(Log_Sensitives=Sensivity_key_create, Log_Process=Process_key_create, Description=Description_key_create, created_by=request.user, MultiTenantName=TenantName)
            HSM_key_create.save()

            KeyN = KeyName + "priv"
            CA_Return = CA_Create_Request(Token_ID,Token_PIN,KeyN, CommonName,OrganizationName,CountryName)
            print(CA_Return)
            file_path = "/app"+str(CA_Return['CA_Sertifikasi'])
            if os.path.exists(file_path):
                ### CRT Create #####
                Sensivity_crt_create = "INFO"
                Process_crt_create = "Signature"
                Description_crt_create = f'Created certificate named {CertificateName}'
                HSM_crt_create  = Logs(Log_Sensitives=Sensivity_crt_create, Log_Process=Process_crt_create, Description=Description_crt_create, created_by=request.user, MultiTenantName=TenantName)

                HSM_crt_create.save()

                file_crt = file_path.split('/')
                CRTName = file_crt[-1]
                Certificate_Load_Request(Token_ID,Token_PIN,CRTName,CertificateName)
                Cer_Info = Certificate_Info_Request(Token_ID,Token_PIN,CertificateName)
                First_Date = Cer_Info[0]['First_Date']
                Last_Date = Cer_Info[0]['Last_Date']
                date_format = "%d/%m/%Y %H:%M:%S"
                First_D = datetime.strptime(First_Date, date_format)
                Last_D = datetime.strptime(Last_Date, date_format)

                token_instance = slotlist.objects.get(TokenName=Token_Name)

                certificates_single = certificates(Slot_ID=Token_ID,Token_Name=token_instance,KeyName=KeyName,Certificate_Name=CertificateName,Common_Name=CommonName,Country_Code=CountryName,Data_Start=First_D,Data_End=Last_D)
                certificates_single._request = request
                certificates_single.save()
            else:
                ### CRT not Create #####
                Sensivity_crt_create_not = "ERROR"
                Process_crt_create_not = "Signature"
                Description_crt_create_not = f'Failed to create certificate named {CertificateName}'
                HSM_crt_create_not  = Logs(Log_Sensitives=Sensivity_crt_create_not, Log_Process=Process_crt_create_not, Description=Description_crt_create_not, created_by=request.user, MultiTenantName=TenantName)
                HSM_crt_create_not.save()

        else:
            pass
        #CA_Create_Full(Token_Name,CertificateName,CommonName,OrganizationName,CountryName,KeyName,KeyBIT)
        return redirect('Certificates_List')
    else:
        # ### Key Create #####
        # Sensivity_key_not = "ERROR"
        # Process_key_not = "Create"
        # Description_key_not = f'Failed to create key named {KeyName}'
        # HSM_key_not  = Logs(Log_Sensitives=Sensivity_key_not, Log_Process=Process_key_not, Description=Description_key_not)
        # HSM_key_not.save()
        return render(request, 'Certificates.html',{'HSM_All_object':HSM_All_object, 'obje':obje, 'UserType':UserType, 'TenantName':TenantName})

@login_required
@user_type_required(user_types=['System_User','Operator_User','Client_User'])
def Keys_List(request):
    UserType = UserProfile.objects.filter(user=request.user.id).values_list('USerType', flat=True).first()
    Token_Name = slotlist.objects.filter(MultiTenantName=TenantName)
    keys_list = keys.objects.filter(created_by=request.user.id, MultiTenantName=TenantName)
    
    multifactor = False
    if request.method == 'POST':
        token_name = request.POST['token_name']
        request.session['token_name'] = token_name
        key_name = request.POST['key_name']
        request.session['key_name'] = key_name
        Key_Type = request.POST['KeyType']
        request.session['Key_Type'] = Key_Type
        if Key_Type == 'AES':
            Key_BIT = request.POST['KeyOptionAES']
            request.session['Key_BIT'] = Key_BIT
        elif Key_Type == 'RSA':
            Key_BIT = request.POST['KeyOptionRSA']
            request.session['Key_BIT'] = Key_BIT
        elif Key_Type == 'EC':
            Key_BIT = request.POST['KeyOptionEC']
            request.session['Key_BIT'] = Key_BIT
        else:
            messages.success(request, 'Key type value is selected incorrectly')
            return redirect('Keys_List')

        #Key_BIT = request.POST['Key_BIT']
        Slot_Info = FindID(token_name)
        if Slot_Info['Message: '] == 'Token not found':
            messages.success(request, 'Token not found')
            return redirect('Keys_List')
        else:
            Token_ID = Slot_Info['Message: ']['slot_id']
        request.session['Token_ID'] = Token_ID
        PIN_Encrypt = slotlist.objects.filter(TokenName=token_name).values_list('UserPIN', flat=True).first()
        Action = "Decrypt"
        result = Slot_PIN_ENC_DEC(Action,PIN_Encrypt)
        print(result)
        json_string = json.dumps(result)
        loaded_data = json.loads(json_string)
        Token_PIN = loaded_data['Message:']['Decrypt Data: ']
        request.session['Token_PIN'] = Token_PIN
        multifactor_value = MultifactorModel.objects.filter(user_factor=request.user.id).values_list('Keys_Create', flat=True).first()
        #multifactor_value = UserProfile.objects.filter(user=request.user).values_list('MulfiFactor', flat=True).first()
        if multifactor_value == 'Disable':
            if Key_Type == 'RSA':
                result = RSA_Create_Request(Token_ID,Token_PIN,key_name, Key_BIT)
                print(result)
                #{'message:': 'RSAKeys2 key was created'}
                if result['message:'] == f'{key_name} key was created':
                    
                    token_instance = slotlist.objects.get(TokenName=token_name)
                    keys_single = keys(SlotID=Token_ID,Token_Name=token_instance,Keys_Type=Key_Type,Keys_Name=key_name,Key_BIT=Key_BIT)
                    keys_single._request = request
                    keys_single.save()
                    ### Key Create #####
                    Sensivity_key_rsa = "INFO"
                    Process_key_rsa = "Create"
                    Description_key_rsa = f'Generated RSA key named {key_name}'
                    HSM_key_rsa  = Logs(Log_Sensitives=Sensivity_key_rsa, Log_Process=Process_key_rsa, Description=Description_key_rsa, created_by=request.user, MultiTenantName=TenantName)
                    HSM_key_rsa.save()
                    messages.success(request, 'RSA Key created.')
                    return redirect('Keys_List')
                    
                    #DB_Keys_INSERT(Slot_ID,Token_Name,Key_Type,key_name,Key_BIT)
                else:
                    message_return = "Failed to generate key"
                    #### Key Log ######
                    Sensivity_key_aes = "ERROR"
                    Process_key_aes = "Create"
                    Description_key_aes = f'Failed to generate key{key_name}'
                    HSM_key_ec  = Logs(Log_Sensitives=Sensivity_key_aes, Log_Process=Process_key_aes, Description=Description_key_aes, created_by=request.user, MultiTenantName=TenantName)
                    HSM_key_ec.save()
                    messages.success(request, 'Failed to generate key')
                    return redirect('Keys_List')
            elif Key_Type == 'AES':
                result = AES_Create_Request(Token_ID,Token_PIN,key_name, Key_BIT)
                print(result)
                # {'message:': 'AESKeys key was created'
                if result['message:'] == f'{key_name} key was created':
                    token_instance = slotlist.objects.get(TokenName=token_name)
                    keys_single = keys(SlotID=Token_ID,Token_Name=token_instance,Keys_Type=Key_Type,Keys_Name=key_name,Key_BIT=Key_BIT)
                    keys_single._request = request
                    keys_single.save()
                    ### Key Create #####
                    Sensivity_key_aes = "INFO"
                    Process_key_aes = "Create"
                    Description_key_aes = f'Generated AES key named {key_name}'
                    HSM_key_aes  = Logs(Log_Sensitives=Sensivity_key_aes, Log_Process=Process_key_aes, Description=Description_key_aes, created_by=request.user, MultiTenantName=TenantName)
                    
                    HSM_key_aes.save()
                    messages.success(request, 'AES Key created.')
                    return redirect('Keys_List')
                else:
                    message_return = "Failed to generate key"
                    print(message_return)
                    #### Key Log ######
                    Sensivity_key_aes = "ERROR"
                    Process_key_aes = "Create"
                    Description_key_aes = f'Failed to generate key{key_name}'
                    HSM_key_ec  = Logs(Log_Sensitives=Sensivity_key_aes, Log_Process=Process_key_aes, Description=Description_key_aes, created_by=request.user, MultiTenantName=TenantName)
                    HSM_key_ec.save()
                    messages.success(request, 'Failed to generate key')
                    return redirect('Keys_List')
            elif Key_Type == 'EC':
                ### Key Create #####
                result = EC_Create(Token_ID,Token_PIN,key_name,Key_BIT)
                #{'message:': 'Created EC Key named ECKeys'}
                if result['message:'] == f'Created EC Key named {key_name}':
                    token_instance = slotlist.objects.get(TokenName=token_name)
                    keys_single = keys(SlotID=Token_ID,Token_Name=token_instance,Keys_Type=Key_Type,Keys_Name=key_name,Key_BIT=Key_BIT)
                    keys_single._request = request
                    keys_single.save()
                    #### Key Log ######
                    Sensivity_key_ec = "INFO"
                    Process_key_ec = "Create"
                    Description_key_ec = f'Generated EC key named {key_name}'
                    HSM_key_ec  = Logs(Log_Sensitives=Sensivity_key_ec, Log_Process=Process_key_ec, Description=Description_key_ec, created_by=request.user, MultiTenantName=TenantName)
                    HSM_key_ec.save()
                    messages.success(request, 'EC Key created.')
                    return redirect('Keys_List')
                else:
                    message_return = "Failed to generate key"
                    #### Key Log ######
                    Sensivity_key_ec = "ERROR"
                    Process_key_ec = "Create"
                    Description_key_ec = f'Failed to generate key{key_name}'
                    HSM_key_ec  = Logs(Log_Sensitives=Sensivity_key_ec, Log_Process=Process_key_ec, Description=Description_key_ec, created_by=request.user, MultiTenantName=TenantName)
                    HSM_key_ec.save()
                    messages.success(request, 'Failed to generate key')
                    return redirect('Keys_List')
            else:
                return redirect('Keys_List')
        else:
            number = UserProfile.objects.filter(user=request.user).values_list('telephone_number', flat=True).first()
            sms_number = Send_SMS(number)
            request.session['sms_number'] = sms_number
            email = User.objects.filter(pk=request.user.pk).values_list('email', flat=True).first()
            mail_number = Mail_numberCreate(email)
            request.session['mail_number'] = mail_number
            return redirect('Multifactor_Keys')

    else:
        return render(request, 'Keys.html',{'Token_Name':Token_Name, 'TenantName':TenantName, 'keys_list':keys_list, 'multifactor':multifactor, 'UserType':UserType})

@login_required
@user_type_required(user_types=['System_User','Operator_User'])
def csr_create(request):
    UserType = UserProfile.objects.filter(user=request.user.id).values_list('USerType', flat=True).first()
    if request.method == 'POST':
        # POST verilerini işleyin
        Keys_Name = request.POST['Keys_Name']
        Country = request.POST['Country']
        City = request.POST['City']
        Company = request.POST['Company']
        Company_Name = request.POST['Company_Name']
        Company_ID = request.POST['Company_ID']
        Token_Names = keys.objects.filter(Keys_Name=Keys_Name).values_list('Token_Name', flat=True).first()
        PIN_Encrypt = slotlist.objects.filter(id=Token_Names).values_list('UserPIN', flat=True).first()
        Action = "Decrypt"
        result = Slot_PIN_ENC_DEC(Action,PIN_Encrypt)
        json_string = json.dumps(result)
        loaded_data = json.loads(json_string)
        Token_PIN = loaded_data['Message:']['Decrypt Data: ']
        Name_Token = slotlist.objects.filter(id=Token_Names).values_list('TokenName', flat=True).first()
        Token_ID = FindID(Name_Token)
        Slot_ID = Token_ID['Message: ']['slot_id']
        KeyPriv = Keys_Name + "priv"
        FilePath = CSR_Create(Slot_ID,Token_PIN,KeyPriv,Country,City,Company,Company_Name,Company_ID)
        Company_csr = Company_Name +".csr"
        with open(FilePath, 'rb') as file:
            csr_data = file.read()
        if os.path.exists(FilePath):
            Sensivity_key_csr = "INFO"
            Process_key_csr = "Signature"
            Description_key_csr = f'Certificate creation was successful'
            HSM_key_csr  = Logs(Log_Sensitives=Sensivity_key_csr, Log_Process=Process_key_csr, Description=Description_key_csr, created_by=request.user, MultiTenantName=TenantName)
            HSM_key_csr.save()
            temp_file = tempfile.NamedTemporaryFile(delete=False, mode='wb')
            temp_file.write(csr_data)
            temp_file.close()
            # Oluşturulan geçici dosyanın yolunu alın
            file_path = temp_file.name
            # HTTP yanıtını oluşturun ve dosyanın içeriğini ekleyin
            response = FileResponse(open(file_path, 'rb'))
            response['Content-Disposition'] = f'attachment; filename="{Company_csr}"'
            # Dosya indirildikten sonra geçici dosyayı silmek için silme işlemini planlayın
            os.unlink(file_path)
            return response
        else:
            # Sertifika dosyası bulunamazsa, Certificates_List sayfasına yönlendirin
            return redirect('Keys_List')
        
        # # İkinci fonksiyonu çağırın ve verileri geçirin
        # result = process_data(pool_name, hsm_slot_name, hsm_slot_pin)
        # if result:
        #     return redirect('Success_View')
        # else:
        #     return redirect('Error_View')
        
    return render(request, 'Keys.html',{'UserType':UserType, 'TenantName':TenantName})

@login_required
@user_type_required(user_types=['System_User','Operator_User','Client_User'])
def Keys_delete(request, id):
    multifactor = False
    request.session['id'] = id
    Object_single = keys.objects.get(id=id)
    TokenName = Object_single.Token_Name
    ID = Object_single.SlotID
    request.session['ID'] = ID
    ObjeLabel = Object_single.Keys_Name
    PIN_Encrypt = slotlist.objects.filter(TokenName=TokenName).values_list('UserPIN', flat=True).first()
    Action = "Decrypt"
    result = Slot_PIN_ENC_DEC(Action,PIN_Encrypt)
    json_string = json.dumps(result)
    loaded_data = json.loads(json_string)
    Token_PIN = loaded_data['Message:']['Decrypt Data: ']
    request.session['Token_PIN'] = Token_PIN
    request.session['ObjeLabel'] = ObjeLabel
    multifactor_value = MultifactorModel.objects.filter(user_factor=request.user.id).values_list('Keys_Delete', flat=True).first()
   # multifactor_value = UserProfile.objects.filter(user=request.user).values_list('MulfiFactor', flat=True).first()
    if multifactor_value == 'Disable':
        if Object_single.Keys_Type == 'AES':
            Type_obje = 'Simetrik'
            Obje_Remove_Request(ID,Token_PIN,Type_obje,ObjeLabel)
            Sensivity_aes_del = "WARNING"
            Process_aes_del = "Delete"
            Description_aes_del = f'AES key named {ObjeLabel} deleted'
            HSM_aes_del = Logs(Log_Sensitives=Sensivity_aes_del, Log_Process=Process_aes_del, Description=Description_aes_del, created_by=request.user, MultiTenantName=TenantName)
            HSM_aes_del.save()
            messages.success(request, 'AES key deleted')
        elif Object_single.Keys_Type == 'RSA':
            Type_public = 'Public'
            ObjeLabel_pub = ObjeLabel+"pub"
            Type_private = 'Private'
            ObjeLabel_priv = ObjeLabel+"priv"
            Obje_Remove_Request(ID,Token_PIN,Type_public,ObjeLabel_pub)
            Sensivity_rsa_del = "WARNING"
            Process_rsa_del = "Delete"
            Description_rsa_del = f'RSA public key named {ObjeLabel_pub} deleted'
            HSM_rsa_del = Logs(Log_Sensitives=Sensivity_rsa_del, Log_Process=Process_rsa_del, Description=Description_rsa_del, created_by=request.user, MultiTenantName=TenantName)
            HSM_rsa_del.save()
            Obje_Remove_Request(ID,Token_PIN,Type_private,ObjeLabel_priv)
            Sensivity_rsa_del_priv = "WARNING"
            Process_rsa_del_priv = "Delete"
            Description_rsa_del_priv = f'RSA private key named {ObjeLabel_pub} deleted'
            HSM_rsa_del_priv = Logs(Log_Sensitives=Sensivity_rsa_del_priv, Log_Process=Process_rsa_del_priv, Description=Description_rsa_del_priv, created_by=request.user, MultiTenantName=TenantName)
            HSM_rsa_del_priv.save()
            messages.success(request, 'RSA key deleted')
        elif Object_single.Keys_Type == 'EC':
            Type_priv = "Private"
            Type_pub = "Public"
            pub = ObjeLabel +"pub"
            priv = ObjeLabel +"priv"
            Obje_Remove_Request(ID,Token_PIN,Type_pub,pub)
            Obje_Remove_Request(ID,Token_PIN,Type_priv,priv)
            Sensivity_rsa_del_priv = "WARNING"
            Process_rsa_del_priv = "Delete"
            Description_rsa_del_priv = f'EC private key named {ObjeLabel} deleted'
            HSM_rsa_del_priv = Logs(Log_Sensitives=Sensivity_rsa_del_priv, Log_Process=Process_rsa_del_priv, Description=Description_rsa_del_priv, created_by=request.user, MultiTenantName=TenantName)
            HSM_rsa_del_priv.save()
            messages.success(request, 'EC key deleted')
        else:
            pass
        #Obje_Remove_Request(ID,PIN,ObjeType,ObjeLabel)
        Object_single.delete()
    else:
        number = UserProfile.objects.filter(user=request.user).values_list('telephone_number', flat=True).first()
        sms_number = Send_SMS(number)
        request.session['sms_number'] = sms_number
        email = User.objects.filter(pk=request.user.pk).values_list('email', flat=True).first()
        mail_number = Mail_numberCreate(email)
        request.session['mail_number'] = mail_number
        return redirect('Multifactor_Keys_Delete')
    return redirect('Keys_List')

@login_required
@user_type_required(user_types=['System_User','Operator_User'])
def Users(request):
    UserType = UserProfile.objects.filter(user=request.user.id).values_list('USerType', flat=True).first()
    TokenName = slotlist.objects.all()
    # User_All = UserAll()
    user = User.objects.get(username=request.user)

    TwoFactor = UserProfile.objects.get(user=user.id)
    Factor = TwoFactor.TwoFactor
    User_All = []
    for Token in TokenName:
        Check_Result = Check_Token_Slot_Request(Token.TokenName)
        if Check_Result == 'healthy':
            # PIN_Encrypt = slotlist.objects.filter(TokenName=Token.TokenName).values_list('UserPIN', flat=True).first()
            # Action = "Decrypt"
            # result = Slot_PIN_ENC_DEC(Action,PIN_Encrypt)
            # json_string = json.dumps(result)
            # loaded_data = json.loads(json_string)
            # Token_PIN = loaded_data['Message:']['Decrypt Data: ']
            Token_PIN = "Default"
            Slot_Info = FindID(Token.TokenName)
            Token_ID = Slot_Info['Message: ']['slot_id']
            Users = Users_Obje_all(Token_ID,Token_PIN)
            User_All += Users
         

    if request.method == 'POST':
        token_name = request.POST['token_name']
        user_name = request.POST['user_name']
        user_parola = request.POST['user_parola']
        try:
            TwoFactor_input = request.POST['TwoFactor']
            print(TwoFactor)
        except:
            TwoFactor_input = None
        
        # PIN_Encrypt = slotlist.objects.filter(TokenName=token_name).values_list('UserPIN', flat=True).first()
        # Action = "Decrypt"
        # result = Slot_PIN_ENC_DEC(Action,PIN_Encrypt)
        # json_string = json.dumps(result)
        # loaded_data = json.loads(json_string)
        # Token_PIN = loaded_data['Message:']['Decrypt Data: ']
        Token_PIN = "Default"
        Token_INFO = TokenIDFind(token_name)
        TokenID = Token_INFO['Message: ']['slot_id']
        if TwoFactor_input is not None:
            user2 = User.objects.get(username=request.user)
            TwoFactor2 = UserProfile.objects.get(user=user2.id)
            totp_secret = TwoFactor2.OTP_Value
            print(TwoFactor_input)
            if verify_totp(totp_secret, TwoFactor):
                print('True')
                User_Create_Request(TokenID,Token_PIN,user_name, user_parola)
                user = User.objects.create_user(user_name, email='', password='')
                UserQR = QRCreate(user_name)
                json_data = json.dumps(UserQR)
                parsed_data = json.loads(json_data)
                Profil_Create = UserProfile.objects.create(user=user, UserType="HSM", TwoFactor="Disable",OTP_Value=parsed_data['user_secret'],QR_Path=parsed_data['IMG_URL'])
                Profil_Create.save()
                Sensivity_user = "INFO"
                Process_user = "Create"
                Description_user = f'user named {user_name} was created'
                hsm_user_create = Logs(Log_Sensitives=Sensivity_user, Log_Process=Process_user, Description=Description_user, created_by=request.user, MultiTenantName=TenantName)
                hsm_user_create.save()
                messages.success(request, 'User Create!')
                return redirect('Users')
            else:
                
                Sensivity_user = "INFO"
                Process_user = "Create"
                Description_user = f'user named {user_name} was not created'
                hsm_user_create = Logs(Log_Sensitives=Sensivity_user, Log_Process=Process_user, Description=Description_user, created_by=request.user, MultiTenantName=TenantName)
                hsm_user_create.save()
                messages.success(request, 'User Not Create!')
                return redirect('Users')
        else:
            User_Create_Request(TokenID,Token_PIN,user_name, user_parola)
            try:
                user = User.objects.create_user(user_name, email='', password='')
            except:
                print("HSM user error-1")
                pass
            UserQR = QRCreate(user_name)
            json_data = json.dumps(UserQR)
            parsed_data = json.loads(json_data)
            try:
                Profil_Create = UserProfile.objects.create(user=user, UserType="HSM", TwoFactor="Disable",OTP_Value=parsed_data['user_secret'],QR_Path=parsed_data['IMG_URL'])
                Profil_Create.save()
            except:
                print("HSM user error-2")
                pass
            # result = User_Create_Request(TokenID,Token_PIN,user_name, user_parola)
            # print(result['user Response'])
            Sensivity_user = "INFO"
            Process_user = "Create"
            Description_user = f'user named {user_name} was created'
            hsm_user_create = Logs(Log_Sensitives=Sensivity_user, Log_Process=Process_user, Description=Description_user, created_by=request.user, MultiTenantName=TenantName)
            hsm_user_create.save()
            #User_Create(token_name,Token_PIN,user_name,user_parola)
            return redirect('Users')

    else:
        return render(request, 'Users.html',{'TokenName':TokenName, 'User_All': User_All, 'Factor':Factor, 'UserType':UserType, 'TenantName':TenantName})

@login_required
@user_type_required(user_types=['System_User','Operator_User'])
def hsm_Users_delete(request, Token_Name, UserName):
    
    # PIN_Encrypt = slotlist.objects.filter(TokenName=Token_Name).values_list('UserPIN', flat=True).first()

    # Action = "Decrypt"
    # result = Slot_PIN_ENC_DEC(Action,PIN_Encrypt)
    # json_string = json.dumps(result)
    # loaded_data = json.loads(json_string)
    # Token_PIN = loaded_data['Message:']['Decrypt Data: ']
    Token_PIN = "Default"
    Token_INFO = TokenIDFind(Token_Name)
    TokenID = Token_INFO['Message: ']['slot_id']
    Users_Obje_Delete(TokenID,Token_PIN,UserName)
    try:
        user_del_db = User.objects.get(username=UserName)
        user_del_db.delete()
    except:
        pass
    Sensivity_user_del = "WARNING"
    Process_user_del = "Delete"
    Description_user_del = f'User {UserName} has been deleted'
    hsm_user_create = Logs(Log_Sensitives=Sensivity_user_del, Log_Process=Process_user_del, Description=Description_user_del, created_by=request.user, MultiTenantName=TenantName)
    hsm_user_create.save()
    #User_Delete(Token_Name,Token_PIN,UserName)
    return redirect('Users')

@login_required
@user_type_required(user_types=['System_User','Operator_User'])
def CRT_Downloads(request, id):
    obje_crt = certificates.objects.get(id=id)
    ID_Slot = obje_crt.Slot_ID
    CRT_Name = obje_crt.Certificate_Name
    CertificateName = CRT_Name +".crt"
    CertificateExport_Request_Message = CertificateExport_Request(ID_Slot,CRT_Name)
    certificate_path = os.path.join('/app/app/CRT/', CertificateName)  # Sertifika dosyasının tam yolu
    if CertificateExport_Request_Message['Message:'] == 'No public key with the specified tag was found.':
        messages.success(request, 'Certificate not found')
        return redirect('Certificates_List')
    else:
        with open(certificate_path, 'rb') as file:
            certificate_data = file.read()
    # try:
    #     with open(certificate_path, 'rb') as file:
    #         certificate_data = file.read()
    # except:
    #     messages.success(request, 'Certificate not found')
    #     return redirect('Certificates_List')
    Sensivity_crt_down = "INFO"
    Process_crt_down = "System"
    Description_crt_down = f'{CertificateName} certificate downloaded'
    hsm_crt_down = Logs(Log_Sensitives=Sensivity_crt_down, Log_Process=Process_crt_down, Description=Description_crt_down, created_by=request.user, MultiTenantName=TenantName)
    hsm_crt_down.save()
    if os.path.exists(certificate_path):
        temp_file = tempfile.NamedTemporaryFile(delete=False, mode='wb')
        temp_file.write(certificate_data)
        temp_file.close()
        # Oluşturulan geçici dosyanın yolunu alın
        file_path = temp_file.name
        # HTTP yanıtını oluşturun ve dosyanın içeriğini ekleyin
        response = FileResponse(open(file_path, 'rb'))
        response['Content-Disposition'] = f'attachment; filename="{CertificateName}"'
        # Dosya indirildikten sonra geçici dosyayı silmek için silme işlemini planlayın
        os.unlink(file_path)
        return response
    else:
        # Sertifika dosyası bulunamazsa, Certificates_List sayfasına yönlendirin
        return redirect('Certificates_List')

@login_required
@user_type_required(user_types=['System_User','Operator_User'])
def CRT_Delete(request, id):

    obje_crt = certificates.objects.get(id=id)
    KeyName = obje_crt.KeyName
    PrivateKey = KeyName+"priv"
    Slot = obje_crt.Slot_ID
    Token_Name = obje_crt.Token_Name
    result_1 = certificates.objects.filter(id=id).values_list('Token_Name', flat=True).first()
    PIN_Encrypt = slotlist.objects.filter(id=result_1).values_list('UserPIN', flat=True).first()
    Action = "Decrypt"
    result = Slot_PIN_ENC_DEC(Action,PIN_Encrypt)
    json_string = json.dumps(result)
    loaded_data = json.loads(json_string)
    print(loaded_data)
    UserPIN = loaded_data['Message:']['Decrypt Data: ']
    CRT_Name = obje_crt.Certificate_Name
    multifactor_value = MultifactorModel.objects.filter(user_factor=request.user.id).values_list('CA_CRT_Delete', flat=True).first()
    #multifactor_value = UserProfile.objects.filter(user=request.user).values_list('MulfiFactor', flat=True).first()
    if multifactor_value == 'Disable':
        find_result = Find_Obje(Slot,UserPIN,PrivateKey)
        if find_result['message'] == 'Found Obje':
            CertType = "Certificate"
            PublicType = "Public"
            PublicKey = KeyName+"pub"
            PrivateType = "Private"
            Obje_Remove_Request(Slot,UserPIN,CertType,CRT_Name)
            Sensivity_crt_del = "WARNING"
            Process_crt_del = "Delete"
            Description_crt_del = f'{CRT_Name} certificate deleted'
            hsm_crt_del = Logs(Log_Sensitives=Sensivity_crt_del, Log_Process=Process_crt_del, Description=Description_crt_del, created_by=request.user, MultiTenantName=TenantName)
            hsm_crt_del.save()
            Obje_Remove_Request(Slot,UserPIN,PublicType,PublicKey)
            Sensivity_pub_del = "WARNING"
            Process_pub_del = "Delete"
            Description_pub_del = f'Deleted public key named {PublicKey}'
            hsm_pub_del = Logs(Log_Sensitives=Sensivity_pub_del, Log_Process=Process_pub_del, Description=Description_pub_del, created_by=request.user, MultiTenantName=TenantName)
            hsm_pub_del.save()
            Obje_Remove_Request(Slot,UserPIN,PrivateType,PrivateKey)
            Sensivity_priv_del = "WARNING"
            Process_priv_del = "Delete"
            Description_priv_del = f'Deleted public key named {PrivateKey}'
            hsm_priv_del = Logs(Log_Sensitives=Sensivity_priv_del, Log_Process=Process_priv_del, Description=Description_priv_del, created_by=request.user, MultiTenantName=TenantName)
            hsm_priv_del.save()
            # CRTAll_File(Slot,UserPIN,KeyName,CRT_Name)
            obje_crt.delete()
        else:
            obje_crt.delete()
    else:
        number = UserProfile.objects.filter(user=request.user).values_list('telephone_number', flat=True).first()
        sms_number = Send_SMS(number)
        request.session['sms_number'] = sms_number
        email = User.objects.filter(pk=request.user.pk).values_list('email', flat=True).first()
        mail_number = Mail_numberCreate(email)
        request.session['mail_number'] = mail_number
        ### Multi Factor ###
        request.session['Slot'] = Slot
        request.session['UserPIN'] = UserPIN
        request.session['CRT_Name'] = CRT_Name
        request.session['KeyName'] = KeyName
        request.session['Cert_Obje_ID'] = id
        return redirect('Multifactor_CRT_Delete')
    return redirect('Certificates_List')

@login_required
@user_type_required(user_types=['System_User','Operator_User'])
def Multifactor_CRT_Delete(request):
    UserType = UserProfile.objects.filter(user=request.user.id).values_list('USerType', flat=True).first()
    HSM_All_object = slotlist.objects.filter(MultiTenantName=TenantName)
    obje = certificates.objects.filter(created_by=request.user.id, MultiTenantName=TenantName)
    #obje = certificates.objects.all()
    multifactor = True
    if request.method == 'POST':
        sms_number = request.session['sms_number']
        mail_number = request.session['mail_number']
        Slot = request.session['Slot']
        UserPIN = request.session['UserPIN']
        CRT_Name = request.session['CRT_Name']
        KeyName = request.session['KeyName']
        sms_name_input = request.POST['sms_name']
        eposta_name_input = request.POST['eposta_name']
        id = request.session['Cert_Obje_ID']
        if sms_name_input == sms_number and eposta_name_input == mail_number:
            PrivateKey = KeyName +"priv"
            find_result = Find_Obje(Slot,UserPIN,PrivateKey)
            obje_crt = certificates.objects.get(id=id)
            if find_result['message'] == 'Found Obje':
                CertType = "Certificate"
                PublicType = "Public"
                PublicKey = KeyName+"pub"
                PrivateType = "Private"
                Obje_Remove_Request(Slot,UserPIN,CertType,CRT_Name)
                Sensivity_crt_del = "WARNING"
                Process_crt_del = "Delete"
                Description_crt_del = f'{CRT_Name} certificate deleted'
                hsm_crt_del = Logs(Log_Sensitives=Sensivity_crt_del, Log_Process=Process_crt_del, Description=Description_crt_del, created_by=request.user, MultiTenantName=TenantName)
                hsm_crt_del.save()
                Obje_Remove_Request(Slot,UserPIN,PublicType,PublicKey)
                Sensivity_pub_del = "WARNING"
                Process_pub_del = "Delete"
                Description_pub_del = f'Deleted public key named {PublicKey}'
                hsm_pub_del = Logs(Log_Sensitives=Sensivity_pub_del, Log_Process=Process_pub_del, Description=Description_pub_del, created_by=request.user, MultiTenantName=TenantName)
                hsm_pub_del.save()
                Obje_Remove_Request(Slot,UserPIN,PrivateType,PrivateKey)
                Sensivity_priv_del = "WARNING"
                Process_priv_del = "Delete"
                Description_priv_del = f'Deleted public key named {PrivateKey}'
                hsm_priv_del = Logs(Log_Sensitives=Sensivity_priv_del, Log_Process=Process_priv_del, Description=Description_priv_del, created_by=request.user, MultiTenantName=TenantName)
                hsm_priv_del.save()
                # CRTAll_File(Slot,UserPIN,KeyName,CRT_Name)
                obje_crt.delete()
            else:
                obje_crt.delete()
            return redirect('Certificates_List')
        else:
            messages.success(request, 'Multi-Factor authentication failed')
            return redirect('Certificates_List')

    return render(request, 'Certificates.html',{'HSM_All_object':HSM_All_object, 'TenantName':TenantName, 'obje':obje, 'multifactor':multifactor, 'UserType':UserType})


@login_required
@user_type_required(user_types=['System_User','Operator_User'])
def Public_Downloads(request, id):
    obje_crt = certificates.objects.get(id=id)
    ID_Slot = obje_crt.Slot_ID
    Keyname = obje_crt.KeyName
    publickey = Keyname+"pub"
    public = publickey +".pem"
    result_1 = certificates.objects.filter(id=id).values_list('Token_Name', flat=True).first()
    PIN_Encrypt = slotlist.objects.filter(id=result_1).values_list('UserPIN', flat=True).first()

    Action = "Decrypt"
    result = Slot_PIN_ENC_DEC(Action,PIN_Encrypt)
    json_string = json.dumps(result)
    loaded_data = json.loads(json_string)
    UserPIN = loaded_data['Message:']['Decrypt Data: ']

    Public_Result = PublicKeyExport_Request(ID_Slot,UserPIN,publickey)
    Public_Result_Meassage = Public_Result['Message:']
    public_path = os.path.join('/app/app/Public/', public)  # Sertifika dosyasının tam yolu
    if Public_Result_Meassage == 'No public key with the specified tag was found.':
        messages.success(request, 'Public key not found')
        return redirect('Certificates_List')
    else:
        with open(public_path, 'rb') as file:
            public_data = file.read()
    # try:

    #     with open(public_path, 'rb') as file:
    #         public_data = file.read()
    # except:
    #     messages.success(request, Public_Result_Meassage)
    #     return redirect('Certificates_List')
    if os.path.exists(public_path):
        Sensivity_priv_down = "INFO"
        Process_priv_down = "System"
        Description_priv_down = f'The public key named {publickey} was downloaded'
        hsm_priv_down = Logs(Log_Sensitives=Sensivity_priv_down, Log_Process=Process_priv_down, Description=Description_priv_down, created_by=request.user, MultiTenantName=TenantName)
        hsm_priv_down.save()
        temp_file = tempfile.NamedTemporaryFile(delete=False, mode='wb')
        temp_file.write(public_data)
        temp_file.close()
        # Oluşturulan geçici dosyanın yolunu alın
        file_path = temp_file.name
        # HTTP yanıtını oluşturun ve dosyanın içeriğini ekleyin
        response = FileResponse(open(file_path, 'rb'))
        response['Content-Disposition'] = f'attachment; filename="{public}"'
        response['X-Reload'] = 'true'
        # Dosya indirildikten sonra geçici dosyayı silmek için silme işlemini planlayın
        
        os.unlink(file_path)
        print(response)
        return response
    else:
        # Sertifika dosyası bulunamazsa, Certificates_List sayfasına yönlendirin
        return redirect('Certificates_List')
    
@login_required
@user_type_required(user_types=['System_User','Operator_User'])
def csr_upload(request):
    if request.method == 'POST' and 'csr_file' in request.FILES:
        csr_file = request.FILES['csr_file']
        CA_Certificate = request.POST['crt_name']
        Company = request.POST['Company_name']
        lifetime = request.POST['lifetime']
        ROOT_PATH = "/app/app/CSR/"
        ROOT_PATH2 = "/app/CSR/"
        Company_Path = ROOT_PATH + str(Company)+ "/"
        if not os.path.exists(Company_Path):
            os.makedirs(Company_Path)
        file_path = os.path.join(Company_Path, csr_file.name)
        file_path_api = ROOT_PATH2 + str(Company) +"/"+csr_file.name
        
        Slot_ID = certificates.objects.filter(Certificate_Name=CA_Certificate).values_list('Slot_ID', flat=True).first()
        KeyName = certificates.objects.filter(Certificate_Name=CA_Certificate).values_list('KeyName', flat=True).first()
        ca_key_name = KeyName +"priv"
        crt_file_name = csr_file.name
        Token_Names = certificates.objects.filter(Certificate_Name=CA_Certificate).values_list('Token_Name', flat=True).first()
        PIN_Encrypt = slotlist.objects.filter(id=Token_Names).values_list('UserPIN', flat=True).first()

        Action = "Decrypt"
        result = Slot_PIN_ENC_DEC(Action,PIN_Encrypt)
        json_string = json.dumps(result)
        loaded_data = json.loads(json_string)
        Token_PIN = loaded_data['Message:']['Decrypt Data: ']

        multifactor_value = MultifactorModel.objects.filter(user_factor=request.user.id).values_list('CSR_HSM_CRT_Request', flat=True).first()

       # multifactor_value = UserProfile.objects.filter(user=request.user).values_list('MulfiFactor', flat=True).first()
        if multifactor_value == 'Disable':
            with open(file_path, 'wb+') as target_file:
                for chunk in csr_file.chunks():
                    target_file.write(chunk)
            
            Sensivity_csr = "INFO"
            Process_csr = "Signature"
            Description_csr = f'Created certificate named {crt_file_name}'
            hsm_csr = Logs(Log_Sensitives=Sensivity_csr, Log_Process=Process_csr, Description=Description_csr, created_by=request.user, MultiTenantName=TenantName)
            hsm_csr.save()
            result = CSR_HSM_CRT_Request(file_path_api,crt_file_name,Company,Token_PIN,Slot_ID,CA_Certificate,ca_key_name,lifetime)
            #return JsonResponse({'success': True, 'message': 'CSR dosyası başarıyla yüklendi.'})
            print(result)
            if result['Message: ']  == 'Certificate generated':
                Download_ROOT = "/app/app/CRT/"
                file_name = crt_file_name.split(".")
                file_name = str(file_name[0]) + ".crt"
                crt_path = os.path.join(Download_ROOT, file_name)  # Sertifika dosyasının tam yolu
                with open(crt_path, 'rb') as file:
                    crt_data = file.read()
                if os.path.exists(crt_path):
                    temp_file = tempfile.NamedTemporaryFile(delete=False, mode='wb')
                    temp_file.write(crt_data)
                    temp_file.close()
                    # Oluşturulan geçici dosyanın yolunu alın
                    file_path = temp_file.name
                    # HTTP yanıtını oluşturun ve dosyanın içeriğini ekleyin
                    response = FileResponse(open(file_path, 'rb'))
                    response['Content-Disposition'] = f'attachment; filename="{file_name}"'
                    # Dosya indirildikten sonra geçici dosyayı silmek için silme işlemini planlayın
                    os.unlink(file_path)
                    return response

            else:
                return redirect('Certificates_List')
        else:
            request.session['file_path_api'] = file_path_api
            request.session['crt_file_name'] = crt_file_name
            request.session['Company'] = Company
            request.session['Token_PIN'] =Token_PIN
            request.session['Slot_ID'] =Slot_ID
            request.session['CA_Certificate'] = CA_Certificate
            request.session['ca_key_name'] = ca_key_name
            request.session['lifetime'] = lifetime
            request.session['csr_file'] = csr_file.read().decode('utf-8')
            number = UserProfile.objects.filter(user=request.user).values_list('telephone_number', flat=True).first()
            sms_number = Send_SMS(number)
            request.session['sms_number'] = sms_number
            email = User.objects.filter(pk=request.user.pk).values_list('email', flat=True).first()
            mail_number = Mail_numberCreate(email)
            request.session['mail_number'] = mail_number
            request.session['crt_file_name'] = crt_file_name
            return redirect('Multifactor_csr_upload')

@login_required
@user_type_required(user_types=['System_User','Operator_User'])
def Multifactor_csr_upload(request):
    UserType = UserProfile.objects.filter(user=request.user.id).values_list('USerType', flat=True).first()
    multifactor = True
    HSM_All_object = slotlist.objects.filter(MultiTenantName=TenantName)
   # obje = certificates.objects.all()
    obje = certificates.objects.filter(created_by=request.user.id,MultiTenantName=TenantName)
    if request.method == 'POST':
        file_path_api = request.session['file_path_api']
        crt_file_name = request.session['crt_file_name']
        Company = request.session['Company']
        Token_PIN = request.session['Token_PIN']
        Slot_ID = request.session['Slot_ID']
        CA_Certificate = request.session['CA_Certificate']
        ca_key_name = request.session['ca_key_name']
        lifetime = request.session['lifetime']
        sms_number = request.session['sms_number']
        mail_number = request.session['mail_number']
        sms_name_input = request.POST['sms_name']
        eposta_name_input = request.POST['eposta_name']
        crt_file_name = request.session['crt_file_name']
        csr_file = request.session.get('csr_file', None)

        ROOT_PATH = "/app/app/CSR/"
        Company_Path = ROOT_PATH + str(Company)+ "/"
        if not os.path.exists(Company_Path):
            os.makedirs(Company_Path)
        file_path = os.path.join(Company_Path, crt_file_name)
        
        if sms_name_input == sms_number and eposta_name_input == mail_number:
            with open(file_path, 'w') as target_file:
                target_file.write(csr_file)
            Sensivity_csr = "INFO"
            Process_csr = "Signature"
            Description_csr = f'Created certificate named {crt_file_name}'
            hsm_csr = Logs(Log_Sensitives=Sensivity_csr, Log_Process=Process_csr, Description=Description_csr, created_by=request.user, MultiTenantName=TenantName)
            hsm_csr.save()
            result = CSR_HSM_CRT_Request(file_path_api,crt_file_name,Company,Token_PIN,Slot_ID,CA_Certificate,ca_key_name,lifetime)
            #return JsonResponse({'success': True, 'message': 'CSR dosyası başarıyla yüklendi.'})
            if result['Message: ']  == 'Certificate generated':
                Download_ROOT = "/app/app/CRT/"
                file_name = crt_file_name.split(".")
                file_name = str(file_name[0]) + ".crt"
                crt_path = os.path.join(Download_ROOT, file_name)  # Sertifika dosyasının tam yolu
                with open(crt_path, 'rb') as file:
                    crt_data = file.read()
                if os.path.exists(crt_path):
                    temp_file = tempfile.NamedTemporaryFile(delete=False, mode='wb')
                    temp_file.write(crt_data)
                    temp_file.close()
                    # Oluşturulan geçici dosyanın yolunu alın
                    file_path = temp_file.name
                    # HTTP yanıtını oluşturun ve dosyanın içeriğini ekleyin
                    response = FileResponse(open(file_path, 'rb'))
                    response['Content-Disposition'] = f'attachment; filename="{file_name}"'
                    # Dosya indirildikten sonra geçici dosyayı silmek için silme işlemini planlayın
                    os.unlink(file_path)
                    return response

            else:
                messages.success(request, 'Certificate could not be generated')
                return redirect('Certificates_List')
    # return redirect('Certificates_List')
    return render(request, 'Certificates.html',{'HSM_All_object':HSM_All_object, 'TenantName':TenantName, 'obje':obje, 'multifactor': multifactor, 'UserType':UserType})

@login_required
@user_type_required(user_types=['System_User','Operator_User'])
def csr_yukle(request):
    UserType = UserProfile.objects.filter(user=request.user.id).values_list('USerType', flat=True).first()
    if request.method == 'POST' and 'csr_file' in request.FILES:
        csr_dosyasi = request.FILES['csr_file']
        
        # CSR dosyasını kaydedilecek dizini belirleyin.
        dosya_dizini = 'dosya_yolu'  # Bu dizini kendi projenizin dosya yolu ile değiştirin.

        if not os.path.exists(dosya_dizini):
            os.makedirs(dosya_dizini)

        dosya_yolu = os.path.join(dosya_dizini, csr_dosyasi.name)

        with open(dosya_yolu, 'wb+') as hedef_dosya:
            for chunk in csr_dosyasi.chunks():
                hedef_dosya.write(chunk)

        return JsonResponse({'success': True, 'message': 'CSR dosyası başarıyla yüklendi.'})

    return render(request, 'csr_yukle.html',{'UserType':UserType, 'TenantName':TenantName})

@login_required
@user_type_required(user_types=['System_User','Operator_User'])
def crt_load(request):
    if request.method == 'POST' and 'crtfile' in request.FILES:
        TokenName = request.POST['token_name']
        crt_file = request.FILES['crtfile']
        crt_file_name = request.POST['crt_file_name']
        PIN_Encrypt = slotlist.objects.filter(TokenName=TokenName).values_list('UserPIN', flat=True).first()
        
        Action = "Decrypt"
        result = Slot_PIN_ENC_DEC(Action,PIN_Encrypt)
        json_string = json.dumps(result)
        loaded_data = json.loads(json_string)
        Token_PIN = loaded_data['Message:']['Decrypt Data: ']

        file_root_crt = "/app/app/CRT/"
        if not os.path.exists(file_root_crt):
            os.makedirs(file_root_crt)
        file_path = os.path.join(file_root_crt, crt_file.name)
        with open(file_path, 'wb+') as target_file:
            for chunk in crt_file.chunks():
                target_file.write(chunk)
        Slot_Info = FindID(TokenName)
        Token_ID = Slot_Info['Message: ']['slot_id']
        CRT_Name = crt_file.name
       # multifactor_value = UserProfile.objects.filter(user=request.user).values_list('MulfiFactor', flat=True).first()
        multifactor_value = MultifactorModel.objects.filter(user_factor=request.user.id).values_list('crt_load_client', flat=True).first()
        if multifactor_value == 'Disable':
            Certificate_Load_Request(Token_ID,Token_PIN,CRT_Name,crt_file_name)
            Sensivity_crt = "INFO"
            Process_crt = "Upload"
            Description_crt = f'certificate named {crt_file_name} has been installed on the HSM device'
            hsm_crt = Logs(Log_Sensitives=Sensivity_crt, Log_Process=Process_crt, Description=Description_crt, created_by=request.user, MultiTenantName=TenantName)
            hsm_crt.save()
            return redirect('Certificates_List')
        else:
            request.session['Token_ID'] = Token_ID
            request.session['Token_PIN'] = Token_PIN
            request.session['CRT_Name'] = CRT_Name
            request.session['crt_file_name'] = crt_file_name
            number = UserProfile.objects.filter(user=request.user).values_list('telephone_number', flat=True).first()
            sms_number = Send_SMS(number)
            request.session['sms_number'] = sms_number
            email = User.objects.filter(pk=request.user.pk).values_list('email', flat=True).first()
            mail_number = Mail_numberCreate(email)
            request.session['mail_number'] = mail_number
            return redirect('Multifactor_crt_load')
    else:
        return redirect('Certificates_List')

@login_required
@user_type_required(user_types=['System_User','Operator_User'])
def Multifactor_crt_load(request):
    UserType = UserProfile.objects.filter(user=request.user.id).values_list('USerType', flat=True).first()
    obje = client_crt.objects.all()
    keysName = keys.objects.values_list('Keys_Name', flat=True)
    multifactor = True
    if request.method == 'POST':
        Token_ID = request.session['Token_ID']
        Token_PIN = request.session['Token_PIN']
        CRT_Name = request.session['CRT_Name']
        crt_file_name = request.session['crt_file_name']
        sms_number = request.session['sms_number']
        mail_number = request.session['mail_number']
        sms_name_input = request.POST['sms_name']
        eposta_name_input = request.POST['eposta_name']
        if sms_name_input == sms_number and eposta_name_input == mail_number:
            Certificate_Load_Request(Token_ID,Token_PIN,CRT_Name,crt_file_name)
            Sensivity_crt = "INFO"
            Process_crt = "Upload"
            Description_crt = f'certificate named {crt_file_name} has been installed on the HSM device'
            hsm_crt = Logs(Log_Sensitives=Sensivity_crt, Log_Process=Process_crt, Description=Description_crt, created_by=request.user, MultiTenantName=TenantName)
            hsm_crt.save()
            return redirect('Certificates_List')
            
    return render(request, 'client_crt.html',{'obje':obje, 'TenantName':TenantName, 'keysName':keysName, 'multifactor':multifactor, 'UserType':UserType})

@login_required
@user_type_required(user_types=['System_User','Operator_User','Client_User'])
def Logs_views(request):
    Logs_File = get_file_info()
    UserType = UserProfile.objects.filter(user=request.user.id).values_list('USerType', flat=True).first()
    if UserType == 'Client_User':
        logs_info = Logs.objects.filter(created_by=request.user.id,MultiTenantName=TenantName).order_by('-id')[:10]
    else:
        logs_info = Logs.objects.filter(MultiTenantName=TenantName).order_by('-id')[:10]
    return render(request, 'Logs.html', {'logs_info':logs_info, 'UserType':UserType, 'TenantName':TenantName, 'Logs_File':Logs_File})
@login_required
@user_type_required(user_types=['System_User','Operator_User','Client_User'])
def Logs_views_number(request,id):
    Logs_File = get_file_info()
    UserType = UserProfile.objects.filter(user=request.user.id).values_list('USerType', flat=True).first()
    
    if UserType == 'Client_User':
        logs_info = Logs.objects.filter(created_by=request.user.id, MultiTenantName=TenantName).order_by('-id')[:id]
    else:
        logs_info = Logs.objects.filter(MultiTenantName=TenantName).order_by('-id')[:id]
    return render(request, 'Logs.html',{'logs_info':logs_info, 'UserType':UserType, 'TenantName':TenantName, 'Logs_File':Logs_File})

@login_required
@user_type_required(user_types=['System_User','Operator_User','Client_User'])
def Client_Cert(request):
    
    UserType = UserProfile.objects.filter(user=request.user.id).values_list('USerType', flat=True).first()
    if UserType == 'Client_User':
        obje = client_crt.objects.filter(created_by=request.user.id, MultiTenantName=TenantName)
    else:
        obje = client_crt.objects.filter(MultiTenantName=TenantName)
    
    keysName = keys.objects.filter(MultiTenantName=TenantName).values_list('Keys_Name', flat=True)
    return render(request, 'client_crt.html',{'obje':obje, 'keysName':keysName, 'UserType':UserType, 'TenantName':TenantName})

@login_required
@user_type_required(user_types=['System_User','Operator_User','Client_User'])
def crt_load_client(request):
    if request.method == 'POST' and 'crtfile' in request.FILES:
        name = request.POST['name']
        key_name = request.POST['key_name']
        crt_file = request.FILES['crtfile']
        crt_file_name = request.POST['crt_file_name']
        TokenName_instance = keys.objects.filter(Keys_Name=key_name).values_list('Token_Name', flat=True).first()
        TokenName_obj = slotlist.objects.filter(pk=TokenName_instance).first()
        TokenName = TokenName_obj.TokenName
        Slot_Info = FindID(TokenName)
        Token_ID = Slot_Info['Message: ']['slot_id']
        PIN_Encrypt = slotlist.objects.filter(TokenName=TokenName).values_list('UserPIN', flat=True).first()

        Action = "Decrypt"
        result = Slot_PIN_ENC_DEC(Action,PIN_Encrypt)
        json_string = json.dumps(result)
        loaded_data = json.loads(json_string)
        PIN_Slot = loaded_data['Message:']['Decrypt Data: ']

        file_root_crt = "/app/app/CRT/"
        if not os.path.exists(file_root_crt):
             os.makedirs(file_root_crt)
        file_path = os.path.join(file_root_crt, crt_file.name)
        with open(file_path, 'wb+') as target_file:
            for chunk in crt_file.chunks():
                target_file.write(chunk)
        CRT_Name = crt_file.name
        Private_Label = key_name + "priv"
        find_result = Find_Obje(Token_ID,PIN_Slot,Private_Label)
        print("Murat Tılsız")
        print(find_result)
        multifactor_value = MultifactorModel.objects.filter(user_factor=request.user.id).values_list('crt_load_client', flat=True).first()
        #multifactor_value = UserProfile.objects.filter(user=request.user).values_list('MulfiFactor', flat=True).first()
        if multifactor_value == 'Disable':
            if find_result['message'] == 'Found Obje':
                Certificate_Load_Request(Token_ID,PIN_Slot,CRT_Name,crt_file_name)
                Sensivity_crt = "INFO"
                Process_crt = "Upload"
                Description_crt = f'certificate named {crt_file_name} has been installed on the HSM device'
                hsm_crt = Logs(Log_Sensitives=Sensivity_crt, Log_Process=Process_crt, Description=Description_crt, created_by=request.user, MultiTenantName=TenantName)
                hsm_crt.save()

                Cer_Info = Certificate_Info_Request(Token_ID,PIN_Slot,crt_file_name)
                #Cer_Info = Certificate_Info_Request(Token_ID,PIN_Slot,crt_file_name)

                First_Date = Cer_Info[0]['First_Date']
                Last_Date = Cer_Info[0]['Last_Date']
                date_format = "%d/%m/%Y %H:%M:%S"
                First_D = datetime.strptime(First_Date, date_format)                
                Last_D = datetime.strptime(Last_Date, date_format)
                instance_token = slotlist.objects.get(TokenName=TokenName)

                CRT_Load = client_crt(name=name, Slot_ID=Token_ID, Token_Name=instance_token, KeyName=key_name, Certificate_Name=crt_file_name, Data_Start=First_D, Data_End=Last_D)
                CRT_Load._request = request
                CRT_Load.save()
                message = "Certificate uploaded"
            else:
                Sensivity_crt = "ERROR"
                Process_crt = "Upload"
                Description_crt = f'certificate named {crt_file_name} has been Not installed on the HSM device'
                hsm_crt = Logs(Log_Sensitives=Sensivity_crt, Log_Process=Process_crt, Description=Description_crt, created_by=request.user, MultiTenantName=TenantName)
                hsm_crt.save()
                message = "Certificate could not be loaded"
            return redirect('Client_Cert')
        else:
            request.session['Token_ID'] = Token_ID
            request.session['PIN_Slot'] = PIN_Slot
            request.session['CRT_Name'] = CRT_Name
            request.session['crt_file_name'] = crt_file_name
            number = UserProfile.objects.filter(user=request.user).values_list('telephone_number', flat=True).first()
            sms_number = Send_SMS(number)
            request.session['sms_number'] = sms_number
            email = User.objects.filter(pk=request.user.pk).values_list('email', flat=True).first()
            mail_number = Mail_numberCreate(email)
            request.session['mail_number'] = mail_number
            request.session['name'] = name
            request.session['key_name'] = key_name
            request.session['TokenName'] = TokenName

            return redirect('Multifactor_crt_load_client')
    else:
        return redirect('Client_Cert')

@login_required
@user_type_required(user_types=['System_User','Operator_User','Client_User'])
def Multifactor_crt_load_client(request):
    UserType = UserProfile.objects.filter(user=request.user.id).values_list('USerType', flat=True).first()
    multifactor = True
    Token_ID = request.session['Token_ID']
    PIN_Slot = request.session['PIN_Slot']
    CRT_Name = request.session['CRT_Name']
    crt_file_name = request.session['crt_file_name']
    sms_number = request.session['sms_number']
    mail_number = request.session['mail_number']
    name = request.session['name']
    key_name = request.session['key_name']
    TokenName = request.session['TokenName']
    Private_Label = key_name + "priv"
    if UserType == 'Client_User':
        obje = client_crt.objects.filter(created_by=request.user.id, MultiTenantName=TenantName)
    else:
        obje = client_crt.objects.filter(MultiTenantName=TenantName)
   # obje = client_crt.objects.all()
    keysName = keys.objects.filter(MultiTenantName=TenantName).values_list('Keys_Name', flat=True)
    if request.method == 'POST':
        sms_name_input = request.POST['sms_name']
        eposta_name_input = request.POST['eposta_name']
        if sms_name_input == sms_number and eposta_name_input == mail_number:
            find_result = Find_Obje(Token_ID,PIN_Slot,Private_Label)
            if find_result['message'] == 'Found Obje':
                Certificate_Load_Request(Token_ID,PIN_Slot,CRT_Name,crt_file_name)
                Sensivity_crt = "INFO"
                Process_crt = "Upload"
                Description_crt = f'certificate named {crt_file_name} has been installed on the HSM device'
                hsm_crt = Logs(Log_Sensitives=Sensivity_crt, Log_Process=Process_crt, Description=Description_crt, created_by=request.user, MultiTenantName=TenantName)
                hsm_crt.save()
                Cer_Info = Certificate_Info_Request(Token_ID,PIN_Slot,crt_file_name)

                First_Date = Cer_Info[0]['First_Date']
                Last_Date = Cer_Info[0]['Last_Date']
                date_format = "%d/%m/%Y %H:%M:%S"
                First_D = datetime.strptime(First_Date, date_format)                
                Last_D = datetime.strptime(Last_Date, date_format)
                instance_token = slotlist.objects.get(TokenName=TokenName)

                CRT_Load = client_crt(name=name, Slot_ID=Token_ID, Token_Name=instance_token, KeyName=key_name, Certificate_Name=crt_file_name, Data_Start=First_D, Data_End=Last_D)
                CRT_Load._request = request
                CRT_Load.save()
                message = "Certificate uploaded"
                messages.success(request, 'Certificate uploaded')
                return redirect('Client_Cert')
            else:
                Sensivity_crt = "ERROR"
                Process_crt = "Upload"
                Description_crt = f'certificate named {crt_file_name} has been Not installed on the HSM device'
                hsm_crt = Logs(Log_Sensitives=Sensivity_crt, Log_Process=Process_crt, Description=Description_crt, created_by=request.user, MultiTenantName=TenantName)
                hsm_crt.save()
                messages.success(request, f'certificate named {crt_file_name} has been Not installed on the HSM device')
                return redirect('Client_Cert')
           # return redirect('Client_Cert')
    return render(request, 'client_crt.html',{'obje':obje, 'keysName':keysName, 'multifactor':multifactor, 'UserType':UserType, 'TenantName':TenantName})



# @login_required
# def SSL_Offloading(request):
#     Client_certificate = client_crt.objects.values_list('name', flat=True)
#     SSL_R = SSL_Rules.objects.all()
#     message = ""
#     if request.method == 'POST':
#         rule_name = request.POST['rule_name']
#         rule_type = request.POST['rule_type']
#         cert_name = request.POST['cert_name']
#         Certificate_Obje = client_crt.objects.get(name=cert_name)
#         token_name = Certificate_Obje.Token_Name
#         priv_name = Certificate_Obje.KeyName
#         crt_name = Certificate_Obje.Certificate_Name
#         pool = slotlist.objects.filter(TokenName=token_name).values_list('HSM_Pool_Name', flat=True).first()
#         pool_1 = hsmpool.objects.get(pk=pool)
#         pool_name = pool_1.HSM_Pool_Name
#         Pool_A_P = hsmpool.objects.filter(HSM_Pool_Name=pool_name).values_list('HSM_Status', flat=True).first()
        
#         tokens = str(token_name)
#         Slot_Info = FindID(tokens)
#         Token_ID = Slot_Info['Message: ']['slot_id']
#         PIN_Encrypt = slotlist.objects.filter(TokenName=token_name).values_list('UserPIN', flat=True).first()

#         Action = "Decrypt"
#         result = Slot_PIN_ENC_DEC(Action,PIN_Encrypt)
#         json_string = json.dumps(result)
#         loaded_data = json.loads(json_string)
#         PIN_Slot = loaded_data['Message:']['Decrypt Data: ']

#         find_result = Find_Obje(Token_ID,PIN_Slot,Private_Label)

#         if Pool_A_P == 'active':
#             #### HSM_Pool_Active ### 
#             tokens = str(token_name)
#             Slot_Info = FindID(tokens)

#             Token_ID = Slot_Info['Message: ']['slot_id']
#             PIN_Encrypt = slotlist.objects.filter(TokenName=token_name).values_list('UserPIN', flat=True).first()

#             Action = "Decrypt"
#             result = Slot_PIN_ENC_DEC(Action,PIN_Encrypt)
#             json_string = json.dumps(result)
#             loaded_data = json.loads(json_string)
#             PIN_Slot = loaded_data['Message:']['Decrypt Data: ']

#             Private_Label = priv_name + "priv"
#             find_result = Find_Obje(Token_ID,PIN_Slot,Private_Label)

#             if find_result['message'] == 'Found Obje':
#                 crt_result = Certificate_Info_Request(Token_ID,PIN_Slot,crt_name)
#                 if len(crt_result) == 0:
#                     message = f'Key named {priv_name} not found'
#                 else:
#                     SSL_Rule = SSL_Rules(Rules_Name=rule_name, Rules_Type=rule_type, HSM_Pool_Name=pool_name, HSM_Token_Name=token_name, Private_key=priv_name, Certificate_Name=crt_name)
#                     SSL_Rule.save()
#             else:
#                 message = f'Key named {priv_name} not found'
#         else:
#             message = f'Please activate the HSM Pool named {pool_name}'

    

        
#         return redirect('SSL_Offloading')
#     else:
        
#         return render(request, 'SSL-Offloading.html',{ 'Client_certificate':Client_certificate, 'SSL_R':SSL_R, 'message':message})


# @login_required
# def SSL_Rule_Delete(request, id):
#     Object_single = SSL_Rules.objects.get(id=id)
#     Object_single.delete()
#     Sensivity = "WARNING"
#     Process = "Delete"
#     Rule_Name = Object_single.Rules_Name
#     Description = f'rule named {Rule_Name} deleted'
#     HSM_Log = Logs(Log_Sensitives=Sensivity, Log_Process=Process, Description=Description, created_by=request.user)
#     HSM_Log.save()
#     return redirect('SSL_Offloading')

# @login_required
# def Dockerfile_Downloads(request, filetype):
#     if filetype == 'Nginx':
#         dockerfile_path = os.path.join('/app/Download/SSL/Nginx/', 'Dockerfile')  # Sertifika dosyasının tam yolu
#         with open(dockerfile_path, 'rb') as file:
#             certificate_data = file.read()
#         Sensivity_crt_down = "INFO"
#         Process_crt_down = "System"
#         Description_crt_down = f'Dockerfile downloaded'
#         hsm_crt_down = Logs(Log_Sensitives=Sensivity_crt_down, Log_Process=Process_crt_down, Description=Description_crt_down, created_by=request.user)
#         hsm_crt_down.save()
#         if os.path.exists(dockerfile_path):
#             temp_file = tempfile.NamedTemporaryFile(delete=False, mode='wb')
#             temp_file.write(certificate_data)
#             temp_file.close()
#             # Oluşturulan geçici dosyanın yolunu alın
#             file_path = temp_file.name
#             # HTTP yanıtını oluşturun ve dosyanın içeriğini ekleyin
#             response = FileResponse(open(file_path, 'rb'))
#             response['Content-Disposition'] = f'attachment; filename="Dockerfile"'
#             # Dosya indirildikten sonra geçici dosyayı silmek için silme işlemini planlayın
#             os.unlink(file_path)
#             return response
#         else:
#             # Sertifika dosyası bulunamazsa, Certificates_List sayfasına yönlendirin
#             return redirect('SSL_Offloading')
#     else:

#         pass
# @login_required
# def NginxConfigDownload(request, RulesName):
#     NginConfSingle = SSL_Rules.objects.get(Rules_Name=RulesName)
#     SlotName = NginConfSingle.HSM_Token_Name
#     PIN_Encrypt = slotlist.objects.filter(TokenName=SlotName).values_list('UserPIN', flat=True).first()

#     Action = "Decrypt"
#     result = Slot_PIN_ENC_DEC(Action,PIN_Encrypt)
#     json_string = json.dumps(result)
#     loaded_data = json.loads(json_string)
#     PIN = loaded_data['Message:']['Decrypt Data: ']

#     Slot_Info = FindID(SlotName)
#     ID = Slot_Info['Message: ']['slot_id']
#     result_nginx = Nginx_SSL_Default(ID,PIN)
#     result_example = Nginx_SSL_Example(ID,PIN)
#     filepath = "/app/Download/SSL/Nginx/nginx.zip"
#     hedef_zip = "/app/Download/SSL/Nginx/nginx.zip"
#     kaynak_klasor = "/app/Download/SSL/Nginx/nginx"
#     if os.path.exists(filepath):
#         os.remove(filepath)
#     else:
#         pass
#     if result_example == result_nginx:
#         with zipfile.ZipFile(hedef_zip, 'w', zipfile.ZIP_DEFLATED) as zipf:
#             for klasor_kok, dizinler, dosyalar in os.walk(kaynak_klasor):
#                 for dosya in dosyalar:
#                     dosya_yolu = os.path.join(klasor_kok, dosya)
#                     dosya_adi = os.path.relpath(dosya_yolu, kaynak_klasor)
#                     zipf.write(dosya_yolu, dosya_adi)
#         nginx_zip_path = os.path.join('/app/Download/SSL/Nginx/', 'nginx.zip')  # Sertifika dosyasının tam yolu
#         with open(nginx_zip_path, 'rb') as file:
#             nginx_zip_data = file.read()
#         temp_file = tempfile.NamedTemporaryFile(delete=False, mode='wb')
#         temp_file.write(nginx_zip_data)
#         temp_file.close()
#             # Oluşturulan geçici dosyanın yolunu alın
#         file_path = temp_file.name
#             # HTTP yanıtını oluşturun ve dosyanın içeriğini ekleyin
#         response = FileResponse(open(file_path, 'rb'))
#         response['Content-Disposition'] = f'attachment; filename="nginx.zip"'
#             # Dosya indirildikten sonra geçici dosyayı silmek için silme işlemini planlayın
#         os.unlink(file_path)
#         return response
            
#     else:
#         messages = "Proccess Faild"
#         return redirect('SSL_Offloading')
# @login_required
# def NginxSSLDownload(request, RulesName):
#     NginSSLSingle = SSL_Rules.objects.get(Rules_Name=RulesName)
#     SlotName = NginSSLSingle.HSM_Token_Name
#     PoolName = NginSSLSingle.HSM_Pool_Name
#     HSM_Pools = hsmpool.objects.get(HSM_Pool_Name=PoolName)
#     IP_Address = HSM_Pools.HSM_IP
#     Port_address =HSM_Pools.HSM_Port
#     PIN_Encrypt = slotlist.objects.filter(TokenName=SlotName).values_list('UserPIN', flat=True).first()
#     Action = "Decrypt"
#     result = Slot_PIN_ENC_DEC(Action,PIN_Encrypt)
#     json_string = json.dumps(result)
#     loaded_data = json.loads(json_string)
#     PIN = loaded_data['Message:']['Decrypt Data: ']
#     # result = WriteNginx(IP_Address,Port_address,PIN)
#     # return result
#     filepath = "/app/Download/SSL/Nginx/SSL.zip"
#     hedef_zip = "/app/Download/SSL/Nginx/SSL.zip"
#     kaynak_klasor = "/app/Download/SSL/Nginx/SSL"
#     if os.path.exists(filepath):
#         os.remove(filepath)
#     else:
#         pass
#     ConfigR = ConfigWrite(IP_Address,Port_address)
#     OpenSSLR = OpenSSLWrite(PIN)

#     if ConfigR == ConfigR:
#         with zipfile.ZipFile(hedef_zip, 'w', zipfile.ZIP_DEFLATED) as zipf:
#             for klasor_kok, dizinler, dosyalar in os.walk(kaynak_klasor):
#                 for dosya in dosyalar:
#                     dosya_yolu = os.path.join(klasor_kok, dosya)
#                     dosya_adi = os.path.relpath(dosya_yolu, kaynak_klasor)
#                     zipf.write(dosya_yolu, dosya_adi)
#         nginx_zip_path = os.path.join('/app/Download/SSL/Nginx/', 'SSL.zip')  # Sertifika dosyasının tam yolu
#         with open(nginx_zip_path, 'rb') as file:
#             nginx_ssl_data = file.read()
#         temp_file = tempfile.NamedTemporaryFile(delete=False, mode='wb')
#         temp_file.write(nginx_ssl_data)
#         temp_file.close()
#             # Oluşturulan geçici dosyanın yolunu alın
#         file_path = temp_file.name
#             # HTTP yanıtını oluşturun ve dosyanın içeriğini ekleyin
#         response = FileResponse(open(file_path, 'rb'))
#         response['Content-Disposition'] = f'attachment; filename="SSL.zip"'
#             # Dosya indirildikten sonra geçici dosyayı silmek için silme işlemini planlayın
#         os.unlink(file_path)
#         return response
#     else:
#         messages = "Proccess Faild"
#         return redirect('SSL_Offloading')
    


@login_required
@user_type_required(user_types=['System_User','Operator_User','Client_User'])
def Public_Downloads_Client(request, id):
    obje_crt_client = client_crt.objects.get(id=id)
    ID_Slot = obje_crt_client.Slot_ID
    Keyname = obje_crt_client.KeyName
    publickey = Keyname+"pub"
    public = publickey +".pem"
    result_1 = client_crt.objects.filter(id=id).values_list('Token_Name', flat=True).first()
    PIN_Encrypt = slotlist.objects.filter(id=result_1).values_list('UserPIN', flat=True).first()

    Action = "Decrypt"
    result = Slot_PIN_ENC_DEC(Action,PIN_Encrypt)
    json_string = json.dumps(result)
    loaded_data = json.loads(json_string)
    UserPIN = loaded_data['Message:']['Decrypt Data: ']

    PublicKeyExport_Request_Message = PublicKeyExport_Request(ID_Slot,UserPIN,publickey)
    print(PublicKeyExport_Request_Message)
    public_path = os.path.join('/app/app/Public/', public)  # Sertifika dosyasının tam yolu
    if PublicKeyExport_Request_Message['Message:'] == 'No public key with the specified tag was found.':
        messages.success(request, 'Public key not found')
        return redirect('Client_Cert')
    else:
        with open(public_path, 'rb') as file:
            public_data = file.read()
    # try:
    #     with open(public_path, 'rb') as file:
    #         public_data = file.read()
    # except:
    #     messages.success(request, 'Public key not found')
    #     return redirect('Client_Cert')
    if os.path.exists(public_path):
        Sensivity_priv_down = "INFO"
        Process_priv_down = "System"
        Description_priv_down = f'The public key named {publickey} was downloaded'
        hsm_priv_down = Logs(Log_Sensitives=Sensivity_priv_down, Log_Process=Process_priv_down, Description=Description_priv_down, created_by=request.user, MultiTenantName=TenantName)
        hsm_priv_down.save()
        temp_file = tempfile.NamedTemporaryFile(delete=False, mode='wb')
        temp_file.write(public_data)
        temp_file.close()
        # Oluşturulan geçici dosyanın yolunu alın
        file_path = temp_file.name
        # HTTP yanıtını oluşturun ve dosyanın içeriğini ekleyin
        response = FileResponse(open(file_path, 'rb'))
        response['Content-Disposition'] = f'attachment; filename="{public}"'
        # Dosya indirildikten sonra geçici dosyayı silmek için silme işlemini planlayın
        os.unlink(file_path)
        return response
    else:
        # Sertifika dosyası bulunamazsa, Certificates_List sayfasına yönlendirin
        return redirect('Client_Cert')
    

@login_required
@user_type_required(user_types=['System_User','Operator_User','Client_User'])
def CRT_Downloads_Client(request, id):
    obje_crt = client_crt.objects.get(id=id)
    ID_Slot = obje_crt.Slot_ID
    CRT_Name = obje_crt.Certificate_Name
    CertificateName = CRT_Name +".crt"
    CertificateExport_Request_Message = CertificateExport_Request(ID_Slot,CRT_Name)
    print(CertificateExport_Request_Message)
    certificate_path = os.path.join('/app/app/CRT/', CertificateName)  # Sertifika dosyasının tam yolu
    if CertificateExport_Request_Message['Message:'] == 'No public key with the specified tag was found.':
        messages.success(request, 'Certificate not found')
        return redirect('Client_Cert')
    else:
        with open(certificate_path, 'rb') as file:
            certificate_data = file.read()
    # try:
    #     with open(certificate_path, 'rb') as file:
    #         certificate_data = file.read()

    # except:
    #     messages.success(request, 'Certificate not found')
    #     return redirect('Client_Cert')
    Sensivity_crt_down = "INFO"
    Process_crt_down = "System"
    Description_crt_down = f'{CertificateName} certificate downloaded'
    hsm_crt_down = Logs(Log_Sensitives=Sensivity_crt_down, Log_Process=Process_crt_down, Description=Description_crt_down, created_by=request.user, MultiTenantName=TenantName)
    hsm_crt_down.save()
    if os.path.exists(certificate_path):
        temp_file = tempfile.NamedTemporaryFile(delete=False, mode='wb')
        temp_file.write(certificate_data)
        temp_file.close()
        # Oluşturulan geçici dosyanın yolunu alın
        file_path = temp_file.name
        # HTTP yanıtını oluşturun ve dosyanın içeriğini ekleyin
        response = FileResponse(open(file_path, 'rb'))
        response['Content-Disposition'] = f'attachment; filename="{CertificateName}"'
        # Dosya indirildikten sonra geçici dosyayı silmek için silme işlemini planlayın
        os.unlink(file_path)
        return response
    else:
        # Sertifika dosyası bulunamazsa, Certificates_List sayfasına yönlendirin
        return redirect('Client_Cert')
    

@login_required
@user_type_required(user_types=['System_User','Operator_User','Client_User'])
def CRT_Delete_Client(request, id):

    obje_crt = client_crt.objects.get(id=id)
    KeyName = obje_crt.KeyName
    PrivateKey = KeyName+"priv"
    Slot = obje_crt.Slot_ID
    Token_Name = obje_crt.Token_Name
    CRT_Name = obje_crt.Certificate_Name
    result_1 = client_crt.objects.filter(id=id).values_list('Token_Name', flat=True).first()
    PIN_Encrypt = slotlist.objects.filter(id=result_1).values_list('UserPIN', flat=True).first()

    Action = "Decrypt"
    result = Slot_PIN_ENC_DEC(Action,PIN_Encrypt)
    json_string = json.dumps(result)
    loaded_data = json.loads(json_string)
    UserPIN = loaded_data['Message:']['Decrypt Data: ']

    multifactor_value = MultifactorModel.objects.filter(user_factor=request.user.id).values_list('CRT_Delete_Client', flat=True).first()
    #multifactor_value = UserProfile.objects.filter(user=request.user).values_list('MulfiFactor', flat=True).first()
    if multifactor_value == 'Disable':
        find_result = Find_Obje(Slot,UserPIN,PrivateKey)
        if find_result['message'] == 'Found Obje':

            CertType = "Certificate"
            Obje_Remove_Request(Slot,UserPIN,CertType,CRT_Name)
            Sensivity_crt_del = "WARNING"
            Process_crt_del = "Delete"
            Description_crt_del = f'{CRT_Name} certificate deleted'
            hsm_crt_del = Logs(Log_Sensitives=Sensivity_crt_del, Log_Process=Process_crt_del, Description=Description_crt_del, created_by=request.user, MultiTenantName=TenantName)
            hsm_crt_del.save()
            obje_crt.delete()
        else:
            obje_crt.delete()
        return redirect('Client_Cert')
    else:
        #### MultiFactor Authentication ####
        request.session['Slot'] = Slot
        request.session['UserPIN'] = UserPIN
        request.session['PrivateKey'] = PrivateKey
        request.session['CRT_Name'] = CRT_Name
        number = UserProfile.objects.filter(user=request.user).values_list('telephone_number', flat=True).first()
        sms_number = Send_SMS(number)
        request.session['sms_number'] = sms_number

        email = User.objects.filter(pk=request.user.pk).values_list('email', flat=True).first()
        mail_number = Mail_numberCreate(email)
        request.session['mail_number'] = mail_number
        request.session['id'] = id
        return redirect('Multifactor_CRT_Delete_Client')

@login_required
@user_type_required(user_types=['System_User','Operator_User','Client_User'])
def Multifactor_CRT_Delete_Client(request):
    UserType = UserProfile.objects.filter(user=request.user.id,MultiTenantName=TenantName).values_list('USerType', flat=True).first()
    if UserType == 'Client_User':
        obje = client_crt.objects.filter(created_by=request.user.id,MultiTenantName=TenantName)
    else:
        obje = client_crt.objects.filter(MultiTenantName=TenantName)
    keysName = keys.objects.filter(MultiTenantName=TenantName).values_list('Keys_Name', flat=True)
    multifactor = True
    Slot = request.session['Slot']
    UserPIN = request.session['UserPIN']
    PrivateKey = request.session['PrivateKey']
    CRT_Name = request.session['CRT_Name']
    sms_number = request.session['sms_number']
    mail_number = request.session['mail_number']
    id = request.session['id']
    if request.method == 'POST':
        sms_name_input = request.POST['sms_name']
        eposta_name_input = request.POST['eposta_name']
        if sms_name_input == sms_number and eposta_name_input == mail_number:
            find_result = Find_Obje(Slot,UserPIN,PrivateKey)
            obje_crt = client_crt.objects.get(id=id)
            if find_result['message'] == 'Found Obje':

                CertType = "Certificate"
                Obje_Remove_Request(Slot,UserPIN,CertType,CRT_Name)
                Sensivity_crt_del = "WARNING"
                Process_crt_del = "Delete"
                Description_crt_del = f'{CRT_Name} certificate deleted'
                hsm_crt_del = Logs(Log_Sensitives=Sensivity_crt_del, Log_Process=Process_crt_del, Description=Description_crt_del, created_by=request.user, MultiTenantName=TenantName)
                hsm_crt_del.save()
                obje_crt.delete()
            else:
                obje_crt.delete()
            return redirect('Client_Cert')
    return render(request, 'client_crt.html',{'obje':obje, 'keysName':keysName, 'multifactor':multifactor, 'UserType':UserType, 'TenantName':TenantName})

@login_required
@user_type_required(user_types=['System_User','Operator_User','Client_User'])
def profile(request):
    UserType = UserProfile.objects.filter(user=request.user.id).values_list('USerType', flat=True).first()
    user_profile, created = UserProfile.objects.get_or_create(user=request.user)
    if request.method == 'POST':
        User_Single = UserProfile.objects.get(user=request.user)
        User_DB = User.objects.get(username=request.user)
        first_Name = request.POST['first_Name']
        last_name = request.POST['last_name']
        email = request.POST['email']
        request.session['first_Name'] = first_Name
        request.session['last_name'] = last_name
        request.session['email'] = email
        User_DB.first_name = first_Name
        User_DB.last_name = last_name
        User_DB.email = email
        phoneNumber = request.POST.get('phoneNumber')
        cleaned_phone_number = phoneNumber.replace("-", "")
        User_Single.telephone_number = cleaned_phone_number
        request.session['cleaned_phone_number'] = cleaned_phone_number
        number = UserProfile.objects.filter(user=request.user).values_list('telephone_number', flat=True).first()
        sms_number = Send_SMS(number)
        request.session['sms_number'] = sms_number
        email = User.objects.filter(pk=request.user.pk).values_list('email', flat=True).first()
        mail_number = Mail_numberCreate(email)
        request.session['mail_number'] = mail_number
        return redirect('Multifactor_profile')
      
    return render(request, 'profile.html',{'user_profile':user_profile, 'UserType':UserType, 'TenantName':TenantName})

@login_required
@user_type_required(user_types=['System_User','Operator_User'])
def Multifactor_profile(request):
    UserType = UserProfile.objects.filter(user=request.user.id).values_list('USerType', flat=True).first()
    multifactor = True
    user_profile, created = UserProfile.objects.get_or_create(user=request.user)
    if request.method == 'POST':
        first_Name = request.session['first_Name']
        last_name = request.session['last_name']
        email = request.session['email']
        cleaned_phone_number = request.session['cleaned_phone_number']
        User_Single = UserProfile.objects.get(user=request.user)
        User_DB = User.objects.get(username=request.user)
        User_DB.first_name = first_Name
        User_DB.last_name = last_name
        User_DB.email = email
        User_Single.telephone_number = cleaned_phone_number
        sms_number = request.session['sms_number']
        mail_number = request.session['mail_number']
        sms_name_input = request.POST['sms_name']
        eposta_name_input = request.POST['eposta_name']

        print(sms_name_input)
        print(sms_number)
        print(eposta_name_input)
        print(mail_number)
        if sms_name_input == sms_number and eposta_name_input == mail_number:
            User_DB.save()
            User_Single.save()
            messages.success(request, 'User profile updated ')
            return redirect('profile')
        else:
            messages.success(request, 'User profile not updated ')
            return redirect('profile')


    return render(request, 'profile.html',{'user_profile':user_profile, 'multifactor':multifactor, 'UserType':UserType, 'TenantName':TenantName})

@login_required
@user_type_required(user_types=['System_User','Operator_User','Client_User'])
def profile_enable(request,user_id):
    
    user_profile = UserProfile.objects.get(id=user_id)
    request.session['User_id'] = user_id
    number = UserProfile.objects.filter(user=request.user).values_list('telephone_number', flat=True).first()
    sms_number = Send_SMS(number)
    request.session['sms_number'] = sms_number
    email = User.objects.filter(pk=request.user.pk).values_list('email', flat=True).first()
    mail_number = Mail_numberCreate(email)
    request.session['mail_number'] = mail_number
    return redirect('Multifactor_profile_enable')

@login_required
@user_type_required(user_types=['System_User','Operator_User','Client_User'])
def Multifactor_profile_enable(request):
    UserType = UserProfile.objects.filter(user=request.user.id).values_list('USerType', flat=True).first()
    user_id = request.session['User_id']
    multifactor = True
    mail_number = request.session['mail_number']
    sms_number = request.session['sms_number']
    user_profile = UserProfile.objects.get(id=user_id)
    user_profile, created = UserProfile.objects.get_or_create(user=request.user)
    if request.method == 'POST':
        sms_name_input = request.POST['sms_name']
        eposta_name_input = request.POST['eposta_name']
        if sms_name_input == sms_number and eposta_name_input == mail_number:
            if user_profile.TwoFactor == 'Disable':
                user_profile.TwoFactor = 'Enable'
                user_profile.save()
                return redirect('profile')
            elif user_profile.TwoFactor == 'Enable':
                user_profile.TwoFactor = 'Disable'
                user_profile.save()
                return redirect('profile')
    return render(request, 'profile.html',{'user_profile':user_profile, 'multifactor':multifactor, 'UserType':UserType, 'TenantName':TenantName})

@login_required
@user_type_required(user_types=['System_User','Operator_User'])
def Multi_enable(request,user_id):
    user_profile = UserProfile.objects.get(id=user_id)
    request.session['User_id'] = user_id

    number = UserProfile.objects.filter(user=request.user).values_list('telephone_number', flat=True).first()
    sms_number = Send_SMS(number)
    request.session['sms_number'] = sms_number
    email = User.objects.filter(pk=request.user.pk).values_list('email', flat=True).first()
    mail_number = Mail_numberCreate(email)
    request.session['mail_number'] = mail_number
    return redirect('Multifactor_Multi_enable')


@login_required
@user_type_required(user_types=['System_User','Operator_User'])
def Multifactor_Multi_enable(request):
    UserType = UserProfile.objects.filter(user=request.user.id).values_list('USerType', flat=True).first()
    user_id = request.session['User_id']
    multifactor = True
    mail_number = request.session['mail_number']
    sms_number = request.session['sms_number']
    user_profile = UserProfile.objects.get(id=user_id)
    user_profile, created = UserProfile.objects.get_or_create(user=request.user)
    if request.method == 'POST':
        sms_name_input = request.POST['sms_name']
        eposta_name_input = request.POST['eposta_name']
        if sms_name_input == sms_number and eposta_name_input == mail_number:
            if user_profile.MulfiFactor == 'Disable':
                user_profile.MulfiFactor = 'Enable'
                user_profile.save()
                return redirect('profile')
            elif user_profile.MulfiFactor == 'Enable':
                user_profile.MulfiFactor = 'Disable'
                user_profile.save()
                return redirect('profile')
    return render(request, 'profile.html',{'user_profile':user_profile, 'multifactor':multifactor, 'UserType':UserType, 'TenantName':TenantName})


def verify_2fa_view(request):
    print("denemeelik")
    UserType = UserProfile.objects.filter(user=request.user.id).values_list('USerType', flat=True).first()
    user_id = request.session.get('authenticated_user')
    Totp = UserProfile.objects.get(user=user_id)
    totp_secret = Totp.OTP_Value
    if not user_id:
        messages.success(request, 'User Not Found.')
        # Oturumda geçerli bir kullanıcı yoksa login sayfasına yönlendir
        return redirect('login')

    user = User.objects.get(pk=user_id)

    if request.method == 'POST':
        user_input = request.POST['user_input']

        # Kullanıcıdan gelen iki faktörlü kodu doğrula
        if verify_totp(totp_secret, user_input):
            my_custom_login(request, user)
            messages.success(request, 'Giriş başarılı!')
            UserType = UserProfile.objects.filter(user=request.user.id).values_list('USerType', flat=True).first()
            if UserType == 'Client_User':
                return redirect('Client_Cert')
            else:
                print("denemelik   "+str(UserType))
                return redirect('index')
        else:
            messages.error(request, 'Geçersiz iki faktörlü doğrulama kodu!')

    return render(request, 'Two-Factor.html',{'UserType':UserType, 'TenantName':TenantName})

@login_required
@user_type_required(user_types=['System_User','Operator_User'])
def deneme(request):
    UserType = UserProfile.objects.filter(user=request.user.id).values_list('USerType', flat=True).first()
    if request.method == 'POST':
        dynamic_select_values = request.POST.getlist('dynamicSelect[]')
        dynamic_input_values = request.POST.getlist('dynamicInput[]')
        print(dynamic_select_values)
        print(dynamic_input_values)
        # dynamic_inputs = request.POST.getlist('dynamic_input[]')
        # dynamic_selects = request.POST.getlist('dynamic_select[]')
        # print(dynamic_inputs)
        # print(dynamic_selects)

        # dataJson = {}
        # for i in range(len(dynamic_selects)):
        #     dataJson[dynamic_selects[i]] = dynamic_inputs[i]
        # # Burada form verileriyle ne yapmak istediğinizi belirtin
        # # Örneğin, veritabanına kaydetme veya başka bir işlem
        # print(dataJson)
        return redirect('deneme')

    return render(request, 'deneme.html',{'UserType':UserType, 'TenantName':TenantName})

@login_required
@user_type_required(user_types=['System_User','Operator_User','Client_User'])
def export_logs_to_csv(request):
    if request.method == 'POST':
        Start_date_str = request.POST.get('Start_date')
        End_date_str = request.POST.get('End_date')
        Start_date = datetime.strptime(Start_date_str, "%Y-%m-%d")
        End_date = datetime.strptime(End_date_str, "%Y-%m-%d")

        Start_day = Start_date.day
        Start_month = Start_date.month
        Start_year = Start_date.year

        End_day = End_date.day
        End_month = End_date.month
        End_year = End_date.year
        start_date = timezone.datetime(Start_year, Start_month, Start_day)
        end_date = timezone.datetime(End_year, End_month, End_day)

        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="logs_export.csv"'

        writer = csv.writer(response)
        
        # CSV başlıklarını yazın
       # writer.writerow(['Log_Sensitives', 'created_by', 'User_Name', 'Log_Process', 'created_at', 'Description'])
        writer.writerow(['Log_Sensitives', 'created_by', 'Log_Process', 'created_at', 'Description'])

        # Verileri çekin ve CSV'ye yazın
        logs_queryset = Logs.objects.filter(created_at__range=(start_date, end_date))
        for log in logs_queryset:
            writer.writerow([log.Log_Sensitives, log.created_by.username, log.Log_Process, log.created_at, log.Description])
           # writer.writerow([log.Log_Sensitives, log.created_by.username, log.User_Name, log.Log_Process, log.created_at, log.Description])

        return response
    else:
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="logs_export.csv"'

        writer = csv.writer(response)
        
        # CSV başlıklarını yazın
        #writer.writerow(['Log_Sensitives', 'created_by', 'User_Name', 'Log_Process', 'created_at', 'Description'])
        writer.writerow(['Log_Sensitives', 'created_by', 'Log_Process', 'created_at', 'Description'])
        # Verileri çekin ve CSV'ye yazın
        logs_queryset = Logs.objects.all()
        for log in logs_queryset:
            #writer.writerow([log.Log_Sensitives, log.created_by.username, log.User_Name, log.Log_Process, log.created_at, log.Description])
            writer.writerow([log.Log_Sensitives, log.created_by.username, log.Log_Process, log.created_at, log.Description])
        
        return response

@login_required
@user_type_required(user_types=['System_User','Operator_User'])
def CA_CRT(request):
    if request.method == 'POST':
        Token_Name = request.POST['Token_Name']
        CertificateName = request.POST['CertificateName']
        KeyName = request.POST['KeyName']
        KeyType = request.POST['KeyType']
        lifetime = request.POST['lifetime']
        dynamic_select_values = request.POST.getlist('dynamicSelect[]')
        dynamic_input_values = request.POST.getlist('dynamicInput[]')
        if KeyType == 'RSA':
            KeyBIT = request.POST['RSAKey']
            request.session['KeyBIT'] = KeyBIT
        elif KeyType == 'EC':
            KeyBIT = request.POST['ECKey']
            request.session['KeyBIT'] = KeyBIT
        DataJson = ""
        for i in range(len(dynamic_select_values)):
            obje = "x509.NameAttribute("+dynamic_select_values[i]+",'"+ dynamic_input_values[i]+"')"
            DataJson = DataJson + obje + "#"
        print(DataJson)
        ### Key Create #####
        PIN_Encrypt = slotlist.objects.filter(TokenName=Token_Name).values_list('UserPIN', flat=True).first()
        Action = "Decrypt"
        result = Slot_PIN_ENC_DEC(Action,PIN_Encrypt)
        json_string = json.dumps(result)
        loaded_data = json.loads(json_string)
        Token_PIN = loaded_data['Message:']['Decrypt Data: ']
        Slot_Info = FindID(Token_Name)
        Token_ID = Slot_Info['Message: ']['slot_id']
        ### Sessions ###
        multifactor_value = MultifactorModel.objects.filter(user_factor=request.user.id).values_list('CA_CRT', flat=True).first()
        #multifactor_value = UserProfile.objects.filter(user=request.user).values_list('MulfiFactor', flat=True).first()

        if multifactor_value == 'Disable':
           # Key_Result = RSA_Create_Request(Token_ID,Token_PIN,KeyName, KeyBIT)
            if KeyType == 'RSA':
                Key_Result = RSA_Create_Request(Token_ID,Token_PIN,KeyName, KeyBIT)
                print(Key_Result)
                #{'message:': 'RSAKeys2 key was created'}
                if Key_Result['message:'] == f'{KeyName} key was created':
                    
                    token_instance = slotlist.objects.get(TokenName=Token_Name)
                    keys_single = keys(SlotID=Token_ID,Token_Name=token_instance,Keys_Type=KeyType,Keys_Name=KeyName,Key_BIT=KeyBIT)
                    keys_single._request = request
                    keys_single.save()
                    ### Key Create #####
                    Sensivity_key_rsa = "INFO"
                    Process_key_rsa = "Create"
                    Description_key_rsa = f'Generated RSA key named {KeyName}'
                    HSM_key_rsa  = Logs(Log_Sensitives=Sensivity_key_rsa, Log_Process=Process_key_rsa, Description=Description_key_rsa, created_by=request.user, MultiTenantName=TenantName)
                    HSM_key_rsa.save()
                    # messages.success(request, 'RSA Key created.')
                    # return redirect('Certificates_List')
                    
                    #DB_Keys_INSERT(Slot_ID,Token_Name,Key_Type,key_name,Key_BIT)
                else:
                    message_return = "Failed to generate key"
                    #### Key Log ######
                    Sensivity_key_aes = "ERROR"
                    Process_key_aes = "Create"
                    Description_key_aes = f'Failed to generate key{KeyName}'
                    HSM_key_ec  = Logs(Log_Sensitives=Sensivity_key_aes, Log_Process=Process_key_aes, Description=Description_key_aes, created_by=request.user, MultiTenantName=TenantName)
                    HSM_key_ec.save()
                    messages.success(request, 'Failed to generate key')
                    return redirect('Certificates_List')
            
            elif KeyType == 'EC':
                ### Key Create #####
                Key_Result = EC_Create(Token_ID,Token_PIN,KeyName,KeyBIT)
                #{'message:': 'Created EC Key named ECKeys'}
                if Key_Result['message:'] == f'Created EC Key named {KeyName}':
                    token_instance = slotlist.objects.get(TokenName=Token_Name)
                    keys_single = keys(SlotID=Token_ID,Token_Name=token_instance,Keys_Type=KeyType,Keys_Name=KeyName,Key_BIT=KeyBIT)
                    keys_single._request = request
                    keys_single.save()
                    #### Key Log ######
                    Sensivity_key_ec = "INFO"
                    Process_key_ec = "Create"
                    Description_key_ec = f'Generated EC key named {KeyName}'
                    HSM_key_ec  = Logs(Log_Sensitives=Sensivity_key_ec, Log_Process=Process_key_ec, Description=Description_key_ec, created_by=request.user, MultiTenantName=TenantName)
                    HSM_key_ec.save()
                    # messages.success(request, 'EC Key created.')
                    # return redirect('Certificates_List')
                else:
                    message_return = "Failed to generate key"
                    #### Key Log ######
                    Sensivity_key_ec = "ERROR"
                    Process_key_ec = "Create"
                    Description_key_ec = f'Failed to generate key{KeyName}'
                    HSM_key_ec  = Logs(Log_Sensitives=Sensivity_key_ec, Log_Process=Process_key_ec, Description=Description_key_ec, created_by=request.user, MultiTenantName=TenantName)
                    HSM_key_ec.save()
                    messages.success(request, 'Failed to generate key')
                    return redirect('Certificates_List')
            if Key_Result['message:'] == f'{KeyName} key was created':
                ####  Logs
                Sensivity_key_create = "INFO"
                Process_key_create = "Create"
                Description_key_create = f'Created key named {KeyName}'
                HSM_key_create  = Logs(Log_Sensitives=Sensivity_key_create, Log_Process=Process_key_create, Description=Description_key_create, created_by=request.user, MultiTenantName=TenantName)
                HSM_key_create.save()  
                Keys_Priv = KeyName +"priv"
                file_path_return = CA_Create_Request_2(Token_ID,Token_PIN,Keys_Priv, lifetime, DataJson)
                try:
                    file_path = file_path_return['CA_Sertifikasi']
                    file_crt = file_path.split('/')
                    CRTName = file_crt[-1]
                    result_CRT = Certificate_Load_Request(Token_ID,Token_PIN,CRTName,CertificateName)
                    Cer_Info = Certificate_Info_Request(Token_ID,Token_PIN,CertificateName)
                    First_Date = Cer_Info[0]['First_Date']
                    Last_Date = Cer_Info[0]['Last_Date']
                    date_format = "%d/%m/%Y %H:%M:%S"
                    First_D = datetime.strptime(First_Date, date_format)
                    Last_D = datetime.strptime(Last_Date, date_format)
                    token_instance = slotlist.objects.get(TokenName=Token_Name)
                    certificates_single = certificates(Slot_ID=Token_ID,Token_Name=token_instance,KeyName=KeyName,Certificate_Name=CertificateName,Data_Start=First_D,Data_End=Last_D)
                    certificates_single._request = request
                    certificates_single.save()
                    messages.success(request, 'CA Certificate create is success')
                    return redirect('Certificates_List')
                except:
                    try:
                        file_path = file_path_return['CA_Sertifikasi']
                        Error = file_path.split(':')
                        return_error = Error[1]
                        # Type_public = 'Public'
                        # ObjeLabel_pub = KeyName+"pub"
                        # Type_private = 'Private'
                        # ObjeLabel_priv = KeyName+"priv"
                        # Obje_Remove_Request(Token_ID,Token_PIN,Type_public,ObjeLabel_pub)
                        # Obje_Remove_Request(Token_ID,Token_PIN,Type_private,ObjeLabel_priv)
                        messages.success(request, return_error)
                        return redirect('Certificates_List')
                    except:
                        error_message = "Entered values are incorrect"
                        messages.success(request, error_message)
                        return redirect('Certificates_List')

            else:
                messages.success(request, 'Key Not Create')
                return redirect('Certificates_List')
        else:
            request.session['Token_ID'] = Token_ID
            request.session['Token_PIN'] = Token_PIN
            request.session['KeyName'] = KeyName
            
            request.session['lifetime'] = lifetime
            request.session['DataJson'] = DataJson
            request.session['CertificateName'] = CertificateName
            request.session['Token_Name'] = Token_Name
            number = UserProfile.objects.filter(user=request.user).values_list('telephone_number', flat=True).first()
            sms_number = Send_SMS(number)
            request.session['sms_number'] = sms_number
            email = User.objects.filter(pk=request.user.pk).values_list('email', flat=True).first()
            mail_number = Mail_numberCreate(email)
            request.session['mail_number'] = mail_number
            return redirect('Multifactor_CA_CRT')

@login_required
@user_type_required(user_types=['System_User','Operator_User'])
def Multifactor_CA_CRT(request):
    UserType = UserProfile.objects.filter(user=request.user.id).values_list('USerType', flat=True).first()
    multifactor = True
    HSM_All_object = slotlist.objects.filter(MultiTenantName=TenantName)
    obje = certificates.objects.filter(created_by=request.user.id,MultiTenantName=TenantName)
   # obje = certificates.objects.all()
    if request.method == 'POST':
        sms_number =  request.session['sms_number']
        mail_number =  request.session['mail_number']
        sms_name_input = request.POST['sms_name']
        eposta_name_input = request.POST['eposta_name']

        Token_ID =  request.session['Token_ID']
        Token_PIN =  request.session['Token_PIN']
        KeyName =  request.session['KeyName']
        KeyBIT =  request.session['KeyBIT']
        lifetime =  request.session['lifetime']
        DataJson =  request.session['DataJson']
        CertificateName =  request.session['CertificateName']
        Token_Name =  request.session['Token_Name']
        if sms_name_input == sms_number and eposta_name_input == mail_number:

            Key_Result = RSA_Create_Request(Token_ID,Token_PIN,KeyName, KeyBIT)
            if Key_Result['message:'] == f'{KeyName} key was created':
                ####  Logs
                Sensivity_key_create = "INFO"
                Process_key_create = "Create"
                Description_key_create = f'Created key named {KeyName}'
                HSM_key_create  = Logs(Log_Sensitives=Sensivity_key_create, Log_Process=Process_key_create, Description=Description_key_create, created_by=request.user, MultiTenantName=TenantName)
                HSM_key_create.save()  
                Keys_Priv = KeyName +"priv"
                file_path_return = CA_Create_Request_2(Token_ID,Token_PIN,Keys_Priv, lifetime, DataJson)
                file_path = file_path_return['CA_Sertifikasi']
                file_crt = file_path.split('/')
                CRTName = file_crt[-1]
                result_CRT = Certificate_Load_Request(Token_ID,Token_PIN,CRTName,CertificateName)
                Cer_Info = Certificate_Info_Request(Token_ID,Token_PIN,CertificateName)
                First_Date = Cer_Info[0]['First_Date']
                Last_Date = Cer_Info[0]['Last_Date']
                date_format = "%d/%m/%Y %H:%M:%S"
                First_D = datetime.strptime(First_Date, date_format)
                Last_D = datetime.strptime(Last_Date, date_format)
                token_instance = slotlist.objects.get(TokenName=Token_Name)
                certificates_single = certificates(Slot_ID=Token_ID,Token_Name=token_instance,KeyName=KeyName,Certificate_Name=CertificateName,Data_Start=First_D,Data_End=Last_D)
                certificates_single._request = request
                certificates_single.save()
                messages.success(request, 'CA Certificate create is success')
                return redirect('Certificates_List')
            else:
                messages.success(request, 'Key Not Create')
                return redirect('Certificates_List')
        else:
            messages.success(request, 'You entered the SMS and e-mail code incorrectly')
            return redirect('Certificates_List')

    return render(request, 'Certificates.html',{'HSM_All_object':HSM_All_object, 'obje':obje, 'multifactor':multifactor, 'UserType':UserType, 'TenantName':TenantName})
    
@login_required
@user_type_required(user_types=['System_User','Operator_User','Client_User'])
def csr_create_new(request):
    UserType = UserProfile.objects.filter(user=request.user.id).values_list('USerType', flat=True).first()
    if request.method == 'POST':
        # POST verilerini işleyin
        Keys_Name = request.POST['Keys_Name']
        dynamic_select_values = request.POST.getlist('dynamicSelect[]')
        dynamic_input_values = request.POST.getlist('dynamicInput[]')
        CommonName = request.POST['CommonName']
        print(Keys_Name)
        print(dynamic_select_values)
        print(dynamic_input_values)
        DataJson = ""
        for i in range(len(dynamic_select_values)):
            obje = "x509.NameAttribute("+dynamic_select_values[i]+",'"+ dynamic_input_values[i]+"')"
            DataJson = DataJson + obje + "#"
        print(DataJson)
        Token_Names = keys.objects.filter(Keys_Name=Keys_Name).values_list('Token_Name', flat=True).first()
        PIN_Encrypt = slotlist.objects.filter(id=Token_Names).values_list('UserPIN', flat=True).first()
        Action = "Decrypt"
        result = Slot_PIN_ENC_DEC(Action,PIN_Encrypt)
        json_string = json.dumps(result)
        loaded_data = json.loads(json_string)
        Token_PIN = loaded_data['Message:']['Decrypt Data: ']
        Name_Token = slotlist.objects.filter(id=Token_Names).values_list('TokenName', flat=True).first()
        Token_ID = FindID(Name_Token)
        Slot_ID = Token_ID['Message: ']['slot_id']
        KeyPriv = Keys_Name + "priv"
        File = CSR_Create_New(Slot_ID,Token_PIN,KeyPriv,CommonName,DataJson)
        FilePath =File['message:']
        print(FilePath)
        # FilePath = CSR_Create(Slot_ID,Token_PIN,KeyPriv,Country,City,Company,Company_Name,Company_ID)
        FilePath = "/app"+str(FilePath)
        if 'Error' in FilePath:
            messages.success(request, 'CSR file could not be created')
            return redirect('Keys_List')
        else:
            Company_csr = CommonName +".csr"
            with open(FilePath, 'rb') as file:
                csr_data = file.read()
            if os.path.exists(FilePath):
                Sensivity_key_csr = "INFO"
                Process_key_csr = "Signature"
                Description_key_csr = f'Certificate creation was successful'
                HSM_key_csr  = Logs(Log_Sensitives=Sensivity_key_csr, Log_Process=Process_key_csr, Description=Description_key_csr, created_by=request.user, MultiTenantName=TenantName)
                HSM_key_csr.save()
                temp_file = tempfile.NamedTemporaryFile(delete=False, mode='wb')
                temp_file.write(csr_data)
                temp_file.close()
                # Oluşturulan geçici dosyanın yolunu alın
                file_path = temp_file.name
                # HTTP yanıtını oluşturun ve dosyanın içeriğini ekleyin
                response = FileResponse(open(file_path, 'rb'))
                response['Content-Disposition'] = f'attachment; filename="{Company_csr}"'
                # Dosya indirildikten sonra geçici dosyayı silmek için silme işlemini planlayın
                os.unlink(file_path)
                return response
                
            else:
                # Sertifika dosyası bulunamazsa, Certificates_List sayfasına yönlendirin
                return redirect('Keys_List')
            
        # # İkinci fonksiyonu çağırın ve verileri geçirin
        # result = process_data(pool_name, hsm_slot_name, hsm_slot_pin)
        # if result:
        #     return redirect('Success_View')
        # else:
        #     return redirect('Error_View')
        
    return render(request, 'Keys.html',{'UserType':UserType, 'TenantName':TenantName})

@login_required
@user_type_required(user_types=['System_User','Operator_User'])
def Valid_Load_Request(request):
    crtfile = request.FILES['crtfile']
    crtfile_name = crtfile.name
    
    Cert_Name = request.POST['Cert_Name']
    token_name = request.POST['token_name']
    PIN_Encrypt = slotlist.objects.filter(TokenName=token_name).values_list('UserPIN', flat=True).first()
    Action = "Decrypt"
    result = Slot_PIN_ENC_DEC(Action,PIN_Encrypt)
    json_string = json.dumps(result)
    loaded_data = json.loads(json_string)
    Token_PIN = loaded_data['Message:']['Decrypt Data: ']
    token_instance = slotlist.objects.get(TokenName=token_name)
    result = certificates.objects.filter(Certificate_Name=Cert_Name,Token_Name=token_instance)
    Token_ID = FindID(token_name)
    Slot_ID = Token_ID['Message: ']['slot_id']
    if len(result) == 0:
        messages.success(request, 'Entered Token information and CA certificate are not compatible')
        return redirect('Certificates_List')
    elif len(result) > 1:
        messages.success(request, 'Found more than one value')
        return redirect('Certificates_List')
    else:
        multifactor_value = MultifactorModel.objects.filter(user_factor=request.user.id).values_list('Valid_Load_Request', flat=True).first()

       # multifactor_value = UserProfile.objects.filter(user=request.user).values_list('MulfiFactor', flat=True).first()
        if multifactor_value == 'Disable':
            CRT_Path = '/app/app/CRT'
            if not os.path.exists(CRT_Path):
                os.makedirs(CRT_Path)
            file_path = os.path.join(CRT_Path, crtfile.name)
            with open(file_path, 'wb+') as target_file:
                for chunk in crtfile.chunks():
                    target_file.write(chunk)
            CRT_Name = str(crtfile.name)
            result_api = CRT_Verifty_Request(Slot_ID,Token_PIN,Cert_Name,CRT_Name)
            print(result_api)
    
            if result_api['Verifty']:
                messages.success(request, 'Certificate Verified')
                return redirect('Certificates_List')
            else:
                messages.success(request, 'Certificate Failed to Verify')
                return redirect('Certificates_List')
        else:
            CRT_Name = str(crtfile.name)
            number = UserProfile.objects.filter(user=request.user).values_list('telephone_number', flat=True).first()
            sms_number = Send_SMS(number)
            request.session['sms_number'] = sms_number
            email = User.objects.filter(pk=request.user.pk).values_list('email', flat=True).first()
            mail_number = Mail_numberCreate(email)
            request.session['mail_number'] = mail_number
            request.session['crtfile_name'] = crtfile_name
            request.session['Slot_ID'] = Slot_ID
            request.session['Token_PIN'] = Token_PIN
            request.session['Cert_Name'] = Cert_Name
            request.session['CRT_Name'] = CRT_Name
            request.session['crtfile'] = crtfile.read().decode('utf-8')
            return redirect('Multifactor_Valid_Load_Request')

@login_required
@user_type_required(user_types=['System_User','Operator_User'])
def Multifactor_Valid_Load_Request(request):
    UserType = UserProfile.objects.filter(user=request.user.id).values_list('USerType', flat=True).first()
    multifactor = True
    HSM_All_object = slotlist.objects.filter(MultiTenantName=TenantName)
    obje = certificates.objects.filter(created_by=request.user.id, MultiTenantName=TenantName)
    CRT_Name = request.session['CRT_Name']
    crt_file_data = request.session.get('crtfile', None)
    Slot_ID = request.session['Slot_ID']
    Token_PIN = request.session['Token_PIN']
    Cert_Name = request.session['Cert_Name']
    if request.method == 'POST':
        sms_number =  request.session['sms_number']
        mail_number =  request.session['mail_number']
        sms_name_input = request.POST['sms_name']
        eposta_name_input = request.POST['eposta_name']
        if sms_name_input == sms_number and eposta_name_input == mail_number:
            CRT_Path = '/app/app/CRT'
            if not os.path.exists(CRT_Path):
                os.makedirs(CRT_Path)
            file_path = os.path.join(CRT_Path, CRT_Name)
            with open(file_path, 'w') as target_file:
                target_file.write(crt_file_data)
            CRT_Name = str(CRT_Name)
           
            result_api = CRT_Verifty_Request(Slot_ID,Token_PIN,Cert_Name,CRT_Name)
            print(result_api)
        
            if result_api['Verifty']:
                messages.success(request, 'Certificate Verified')
                return redirect('Certificates_List')
            else:
                messages.success(request, 'Certificate Failed to Verify')
                return redirect('Certificates_List')
            #return redirect('Certificates_List')
        else:
            messages.success(request, 'You entered the SMS and e-mail code incorrectly')
            return redirect('Certificates_List')
        
    return render(request, 'Certificates.html',{'HSM_All_object':HSM_All_object, 'obje':obje, 'multifactor':multifactor, 'UserType':UserType, 'TenantName':TenantName})

@login_required
@user_type_required(user_types=['System_User','Operator_User','Client_User'])
def Valid_Key_CRT(request):
    Keys_Name = request.POST['Keys_Name']
    crtfile = request.FILES['crtfile']
    SlotID = keys.objects.filter(Keys_Name=Keys_Name).values_list('SlotID', flat=True).first()
    Token_Name = keys.objects.filter(Keys_Name=Keys_Name).values_list('Token_Name', flat=True).first()
    Token_Name_real = slotlist.objects.get(id=Token_Name)
    PIN_Encrypt = Token_Name_real.UserPIN
    Action = "Decrypt"
    result = Slot_PIN_ENC_DEC(Action,PIN_Encrypt)
    json_string = json.dumps(result)
    loaded_data = json.loads(json_string)
    Token_PIN = loaded_data['Message:']['Decrypt Data: ']
    print(Token_PIN)
    CRT_Path = '/app/app/CRT'
    if not os.path.exists(CRT_Path):
        os.makedirs(CRT_Path)
    file_path = os.path.join(CRT_Path, crtfile.name)
    with open(file_path, 'wb+') as target_file:
        for chunk in crtfile.chunks():
            target_file.write(chunk)
    CRT_Name = str(crtfile.name)
    print(CRT_Name)
    KeyName = Keys_Name + "pub"
    result = CRT_Key_Verifty_Request(SlotID,Token_PIN,KeyName,CRT_Name)
    messages.success(request, result['message:'])
    return redirect('Keys_List')

@login_required
@user_type_required(user_types=['System_User','Operator_User','Client_User'])
def Multifactor_Keys(request):
    UserType = UserProfile.objects.filter(user=request.user.id).values_list('USerType', flat=True).first()
    multifactor = True
    Token_Name = slotlist.objects.filter(MultiTenantName=TenantName)
    keys_list = keys.objects.filter(created_by=request.user.id, MultiTenantName=TenantName)
    if request.method == 'POST':
        Token_ID = request.session.get('Token_ID')
        Token_PIN = request.session.get('Token_PIN')
        Key_Type = request.session.get('Key_Type')
        Key_BIT = request.session.get('Key_BIT')
        key_name = request.session.get('key_name')
        token_name = request.session.get('token_name')
        sms_name_input = request.POST['sms_name']
        eposta_name_input = request.POST['eposta_name']
        sms_number =  request.session['sms_number']
        mail_number =  request.session['mail_number']

        if sms_name_input == sms_number and eposta_name_input == mail_number:

            if Key_Type == 'RSA':
                result = RSA_Create_Request(Token_ID,Token_PIN,key_name, Key_BIT)
                print(result)
                #{'message:': 'RSAKeys2 key was created'}
                if result['message:'] == f'{key_name} key was created':
                    
                    token_instance = slotlist.objects.get(TokenName=token_name)
                    keys_single = keys(SlotID=Token_ID,Token_Name=token_instance,Keys_Type=Key_Type,Keys_Name=key_name,Key_BIT=Key_BIT)
                    keys_single._request = request
                    keys_single.save()
                    ### Key Create #####
                    Sensivity_key_rsa = "INFO"
                    Process_key_rsa = "Create"
                    Description_key_rsa = f'Generated RSA key named {key_name}'
                    HSM_key_rsa  = Logs(Log_Sensitives=Sensivity_key_rsa, Log_Process=Process_key_rsa, Description=Description_key_rsa, created_by=request.user, MultiTenantName=TenantName)
                    HSM_key_rsa.save()
                    return redirect('Keys_List')
                    #messages.success(request, 'RSA Key created.')
                    
                    #DB_Keys_INSERT(Slot_ID,Token_Name,Key_Type,key_name,Key_BIT)
                else:
                    message_return = "Failed to generate key"
                    #### Key Log ######
                    Sensivity_key_aes = "ERROR"
                    Process_key_aes = "Create"
                    Description_key_aes = f'Failed to generate key{key_name}'
                    HSM_key_ec  = Logs(Log_Sensitives=Sensivity_key_aes, Log_Process=Process_key_aes, Description=Description_key_aes, created_by=request.user, MultiTenantName=TenantName)
                    HSM_key_ec.save()
                    messages.success(request, 'Failed to generate key')
                    return redirect('Keys_List')
            elif Key_Type == 'AES':
                result = AES_Create_Request(Token_ID,Token_PIN,key_name, Key_BIT)
                print(result)
                # {'message:': 'AESKeys key was created'
                if result['message:'] == f'{key_name} key was created':
                    token_instance = slotlist.objects.get(TokenName=token_name)
                    keys_single = keys(SlotID=Token_ID,Token_Name=token_instance,Keys_Type=Key_Type,Keys_Name=key_name,Key_BIT=Key_BIT)
                    keys_single._request = request
                    keys_single.save()
                    ### Key Create #####
                    Sensivity_key_aes = "INFO"
                    Process_key_aes = "Create"
                    Description_key_aes = f'Generated AES key named {key_name}'
                    HSM_key_aes  = Logs(Log_Sensitives=Sensivity_key_aes, Log_Process=Process_key_aes, Description=Description_key_aes, created_by=request.user, MultiTenantName=TenantName)
                    HSM_key_aes.save()
                    messages.success(request, 'AES Key created.')
                    return redirect('Keys_List')
                else:
                    message_return = "Failed to generate key"
                    print(message_return)
                    #### Key Log ######
                    Sensivity_key_aes = "ERROR"
                    Process_key_aes = "Create"
                    Description_key_aes = f'Failed to generate key{key_name}'
                    HSM_key_ec  = Logs(Log_Sensitives=Sensivity_key_aes, Log_Process=Process_key_aes, Description=Description_key_aes, created_by=request.user, MultiTenantName=TenantName)
                    HSM_key_ec.save()
                    messages.success(request, 'Failed to generate key')
                    return redirect('Keys_List')
            elif Key_Type == 'EC':
                ### Key Create #####
                result = EC_Create(Token_ID,Token_PIN,key_name,Key_BIT)
                #{'message:': 'Created EC Key named ECKeys'}
                if result['message:'] == f'Created EC Key named {key_name}':
                    token_instance = slotlist.objects.get(TokenName=token_name)
                    keys_single = keys(SlotID=Token_ID,Token_Name=token_instance,Keys_Type=Key_Type,Keys_Name=key_name,Key_BIT=Key_BIT)
                    keys_single._request = request
                    keys_single.save()
                    #### Key Log ######
                    Sensivity_key_ec = "INFO"
                    Process_key_ec = "Create"
                    Description_key_ec = f'Generated EC key named {key_name}'
                    HSM_key_ec  = Logs(Log_Sensitives=Sensivity_key_ec, Log_Process=Process_key_ec, Description=Description_key_ec, created_by=request.user, MultiTenantName=TenantName)
                    HSM_key_ec.save()
                    messages.success(request, 'EC Key created.')
                    return redirect('Keys_List')
                else:
                    message_return = "Failed to generate key"
                    #### Key Log ######
                    Sensivity_key_ec = "ERROR"
                    Process_key_ec = "Create"
                    Description_key_ec = f'Failed to generate key{key_name}'
                    HSM_key_ec  = Logs(Log_Sensitives=Sensivity_key_ec, Log_Process=Process_key_ec, Description=Description_key_ec, created_by=request.user, MultiTenantName=TenantName)
                    HSM_key_ec.save()
                    messages.success(request, 'Failed to generate key')
                    return redirect('Keys_List')
            else:
                pass
        else:
            messages.success(request, 'You entered the SMS and e-mail code incorrectly')
            return redirect('Keys_List')
        ###Buradan ####
        #Token_ID = Slot_Info['Message: ']['slot_id']
        #Create(token_name,Key_Type,key_name,Key_BIT)
        
        return redirect('Keys_List')
    return render(request, 'Keys.html',{'multifactor':multifactor, 'Token_Name':Token_Name, 'keys_list':keys_list, 'UserType':UserType, 'TenantName':TenantName})

@login_required
@user_type_required(user_types=['System_User','Operator_User','Client_User'])
def Multifactor_Keys_Delete(request):
    UserType = UserProfile.objects.filter(user=request.user.id).values_list('USerType', flat=True).first()
    multifactor = True
    Token_Name = slotlist.objects.filter(MultiTenantName=TenantName)
    keys_list = keys.objects.filter(created_by=request.user.id,MultiTenantName=TenantName)
    if request.method == 'POST':
        sms_number =  request.session['sms_number']
        mail_number =  request.session['mail_number']
        sms_name_input = request.POST['sms_name']
        eposta_name_input = request.POST['eposta_name']
        if sms_name_input == sms_number and eposta_name_input == mail_number:
            id = request.session['id']
            Object_single = keys.objects.get(id=id)
            ID = request.session['ID']
            Token_PIN = request.session['Token_PIN']
            ObjeLabel = request.session['ObjeLabel']
            if Object_single.Keys_Type == 'AES':
                Type_obje = 'Simetrik'
                Obje_Remove_Request(ID,Token_PIN,Type_obje,ObjeLabel)
                Sensivity_aes_del = "WARNING"
                Process_aes_del = "Delete"
                Description_aes_del = f'AES key named {ObjeLabel} deleted'
                HSM_aes_del = Logs(Log_Sensitives=Sensivity_aes_del, Log_Process=Process_aes_del, Description=Description_aes_del, created_by=request.user, MultiTenantName=TenantName)
                HSM_aes_del.save()
                messages.success(request, 'AES key deleted')
            elif Object_single.Keys_Type == 'RSA':
                Type_public = 'Public'
                ObjeLabel_pub = ObjeLabel+"pub"
                Type_private = 'Private'
                ObjeLabel_priv = ObjeLabel+"priv"
                Obje_Remove_Request(ID,Token_PIN,Type_public,ObjeLabel_pub)
                Sensivity_rsa_del = "WARNING"
                Process_rsa_del = "Delete"
                Description_rsa_del = f'RSA public key named {ObjeLabel_pub} deleted'
                HSM_rsa_del = Logs(Log_Sensitives=Sensivity_rsa_del, Log_Process=Process_rsa_del, Description=Description_rsa_del, created_by=request.user, MultiTenantName=TenantName)
                HSM_rsa_del.save()
                Obje_Remove_Request(ID,Token_PIN,Type_private,ObjeLabel_priv)
                Sensivity_rsa_del_priv = "WARNING"
                Process_rsa_del_priv = "Delete"
                Description_rsa_del_priv = f'RSA private key named {ObjeLabel_pub} deleted'
                HSM_rsa_del_priv = Logs(Log_Sensitives=Sensivity_rsa_del_priv, Log_Process=Process_rsa_del_priv, Description=Description_rsa_del_priv, created_by=request.user, MultiTenantName=TenantName)
                HSM_rsa_del_priv.save()
                messages.success(request, 'RSA key deleted')
            elif Object_single.Keys_Type == 'EC':
                Type = "pass"
                Obje_Remove_Request(ID,Token_PIN,Type,ObjeLabel)
                Sensivity_rsa_del_priv = "WARNING"
                Process_rsa_del_priv = "Delete"
                Description_rsa_del_priv = f'EC private key named {ObjeLabel} deleted'
                HSM_rsa_del_priv = Logs(Log_Sensitives=Sensivity_rsa_del_priv, Log_Process=Process_rsa_del_priv, Description=Description_rsa_del_priv, created_by=request.user, MultiTenantName=TenantName)
                HSM_rsa_del_priv.save()
                messages.success(request, 'EC key deleted')
                
            else:
                pass
            #Obje_Remove_Request(ID,PIN,ObjeType,ObjeLabel)
            Object_single.delete()
            return redirect('Keys_List')
        else:
            messages.success(request, 'You entered the SMS and e-mail code incorrectly')
            return redirect('Keys_List')
    return render(request, 'Keys.html',{'multifactor':multifactor, 'Token_Name':Token_Name, 'keys_list':keys_list, 'UserType':UserType, 'TenantName':TenantName})

@login_required
@user_type_required(user_types=['System_User','Operator_User'])
def HSM_Certificate(request):
    UserType = UserProfile.objects.filter(user=request.user.id).values_list('USerType', flat=True).first()
    obje = []
    S_List = slotlist.objects.all()
    for Slot in S_List:
        TokenName = Slot.TokenName
        Token_ID = FindID(TokenName)
        if Token_ID['Message: '] == 'Token not found':
            pass
        else:
            Slot_ID = Token_ID['Message: ']['slot_id']
            print(Slot_ID)
            PIN_Encrypt = slotlist.objects.filter(TokenName=TokenName).values_list('UserPIN', flat=True).first()
            Action = "Decrypt"
            result = Slot_PIN_ENC_DEC(Action,PIN_Encrypt)
            json_string = json.dumps(result)
            loaded_data = json.loads(json_string)
            Token_PIN = loaded_data['Message:']['Decrypt Data: ']
            print(Token_PIN)
            cert_all = Certificate_ALL(Slot_ID,Token_PIN)
            for cert in cert_all:
                obje.append(cert)
        
    return render(request, 'HSM_Certificate.html',{'obje':obje, 'UserType':UserType, 'TenantName':TenantName})

@login_required
@user_type_required(user_types=['System_User','Operator_User'])
def Rules_view(request):
    UserType = UserProfile.objects.filter(user=request.user.id).values_list('USerType', flat=True).first()
    obje = []
    S_List = slotlist.objects.filter(MultiTenantName=TenantName)
    if UserType == 'Operator_User':
        User_Name = UserProfile.objects.select_related('user').filter(USerType='Client_User',MultiTenantName=TenantName).order_by('user__id')
    else:
        User_Name = User.objects.all()
    Rules_Obje = Rules.objects.filter(created_by=request.user.id, MultiTenantName=TenantName)
    for Slot in S_List:
        TokenName = Slot.TokenName
        Token_ID = FindID(TokenName)
        if Token_ID['Message: '] == 'Token not found':
            pass
        else:
            Slot_ID = Token_ID['Message: ']['slot_id']
            PIN_Encrypt = slotlist.objects.filter(TokenName=TokenName).values_list('UserPIN', flat=True).first()
            Action = "Decrypt"
            result = Slot_PIN_ENC_DEC(Action,PIN_Encrypt)
            json_string = json.dumps(result)
            loaded_data = json.loads(json_string)
            Token_PIN = loaded_data['Message:']['Decrypt Data: ']
            cert_all = Certificate_ALL(Slot_ID,Token_PIN)
            for cert in cert_all:
                obje.append(cert)
    if request.method == 'POST':
        hsm_certificate_rule_name = request.POST['hsm_certificate_rule_name']
        hsm_certificate_name = request.POST['hsm_certificate_name']
        certificate_stay_days = request.POST['certificate_stay_days']
        hsm_certificate_user_name = request.POST['hsm_certificate_user_name']

        hsm_certificate_dict = ast.literal_eval(hsm_certificate_name)
        Slot_Name = hsm_certificate_dict['Slot_Label']
        Slot_ID_New = hsm_certificate_dict['Slot_ID']
        Certificate_Name = hsm_certificate_dict['Certificate_Name']
        ### Pool Name ###
        HSM_Pool_Name = slotlist.objects.filter(TokenName=Slot_Name).values_list('HSM_Pool_Name', flat=True).first()
        
        Pool_Name = hsmpool.objects.filter(id=HSM_Pool_Name).values_list('HSM_Pool_Name', flat=True).first()
        print("Pool Name: "+str(Pool_Name))
        ### Date Meselesi ####
        gelecek_tarih_string = hsm_certificate_dict['Last_Date']
        gelecek_tarih = datetime.strptime(gelecek_tarih_string, "%d/%m/%Y %H:%M:%S")
        # Bugünün tarihini alma
        bugun = datetime.now()
        # Kaç gün kaldığını hesapla
        kalan_gun = (gelecek_tarih - bugun).days
        if kalan_gun > 0:
            print("gecerli")
            tarih_string = hsm_certificate_dict['Last_Date']
            tarih_obj = datetime.strptime(tarih_string, "%d/%m/%Y %H:%M:%S")
            # Belirli gün sayısını çıkarma
            yeni_tarih_obj = tarih_obj - timedelta(days=int(certificate_stay_days))
            # Yeni tarihi string formatına çevirme
            yeni_tarih_string = yeni_tarih_obj.strftime("%d/%m/%Y %H:%M:%S")
            print(yeni_tarih_string)
            date_format = "%d/%m/%Y %H:%M:%S"

            # String'i datetime nesnesine çevirin
            sending_time = datetime.strptime(yeni_tarih_string, date_format)

            # Tarihi Django'nun beklediği formata çevirin
            formatted_sending_time = timezone.make_aware(sending_time)
            new_rule = Rules(
                Rules_Name=hsm_certificate_rule_name,
                Pool_Name=Pool_Name,
                SlotName=Slot_Name,
                SlotID=Slot_ID_New,
                Certificate_Name=Certificate_Name,
                Sending_Time=formatted_sending_time,
                Sending_Person=hsm_certificate_user_name
            )
            new_rule._request = request
            new_rule.save()
            
        else:
            print("gercersiz")
    return render(request, 'Rules.html',{'obje':obje, 'User_Name':User_Name, 'Rules_Obje':Rules_Obje, 'UserType':UserType, 'TenantName':TenantName})

@login_required
@user_type_required(user_types=['System_User','Operator_User'])
def Rules_delete(request, str_name):
    Object_single = Rules.objects.get(Rules_Name=str_name),
    Object_single[0].delete()
    return redirect('Rules_view')

@login_required
@user_type_required(user_types=['System_User','Operator_User'])
def Users_All(request):
    UserType = UserProfile.objects.filter(user=request.user.id).values_list('USerType', flat=True).first()
    print(UserType)
   # users_all = UserProfile.objects.select_related('user').all().order_by('user__id')
   # users_all = UserProfile.objects.select_related('user').all().order_by('user__id')
    if UserType == 'Operator_User':
        users_all = UserProfile.objects.select_related('user').filter(USerType='Client_User').order_by('user__id')
    else:
        users_all = UserProfile.objects.select_related('user').all().order_by('user__id')
    multifactor_list = MultifactorModel.objects.all()
    # if request.method == 'POST':
    #     # Checkbox'ların isimlerini alın
    #     checkbox_names = ['Keys_Create', 'Valid_Load_Request', 'CA_CRT', 'CRT_Delete_Client', 'crt_load_client', 'CSR_HSM_CRT_Request', 'CA_CRT_Delete', 'Keys_Delete', 'Slot_delete', 'hsm_slot_update','Slot_List', 'Pool_Active', 'Pool_delete', 'Pool_create']  # Checkbox isimlerini kendi uygulamanıza ve sayfanıza göre güncelleyin

    #     for checkbox_name in checkbox_names:
    #         # Checkbox'ın seçili olup olmadığını kontrol edin
    #         if checkbox_name in request.POST:

    #             print(f"{checkbox_name} seçili.")
    #         else:
    #             # Checkbox seçili değilse buraya gelecek işlemleri yapabilirsiniz
    #             print(f"{checkbox_name} seçili değil.")
    return render(request, 'Users_All.html', {'users_all':users_all, 'multifactor_list':multifactor_list, 'UserType':UserType, 'TenantName':TenantName})

@login_required
@user_type_required(user_types=['System_User','Operator_User'])
def Users_All_Update(request, id):

    if request.method == 'POST':
        # Checkbox'ların isimlerini alın

        user_id = UserProfile.objects.filter(id=id).values_list('user_id', flat=True).first()
        Single_obje = MultifactorModel.objects.get(user_factor=user_id)
        checkbox_names = ['Keys_Create', 'Valid_Load_Request', 'CA_CRT', 'CRT_Delete_Client', 'crt_load_client', 'CSR_HSM_CRT_Request', 'CA_CRT_Delete', 'Keys_Delete', 'Slot_delete', 'hsm_slot_update','Slot_List', 'Pool_Active', 'Pool_delete', 'Pool_create','Pool_Upload']  # Checkbox isimlerini kendi uygulamanıza ve sayfanıza göre güncelleyin

        for checkbox_name in checkbox_names:
            # Checkbox'ın seçili olup olmadığını kontrol edin
            if checkbox_name in request.POST:
                if checkbox_name == 'Keys_Create':
                    Single_obje.Keys_Create = 'Enable'
                elif checkbox_name == 'Valid_Load_Request':
                    Single_obje.Valid_Load_Request = 'Enable'
                elif checkbox_name == 'CA_CRT':
                    Single_obje.CA_CRT = 'Enable'
                elif checkbox_name == 'CRT_Delete_Client':
                    Single_obje.CRT_Delete_Client = 'Enable'
                elif checkbox_name == 'crt_load_client':
                    Single_obje.crt_load_client = 'Enable'
                elif checkbox_name == 'CSR_HSM_CRT_Request':
                    Single_obje.CSR_HSM_CRT_Request = 'Enable'
                elif checkbox_name == 'CA_CRT_Delete':
                    Single_obje.CA_CRT_Delete = 'Enable'
                elif checkbox_name == 'Keys_Delete':
                    Single_obje.Keys_Delete = 'Enable'
                elif checkbox_name == 'Slot_delete':
                    Single_obje.Slot_delete = 'Enable'
                elif checkbox_name == 'hsm_slot_update':
                    Single_obje.hsm_slot_update = 'Enable'
                elif checkbox_name == 'Slot_List':
                    Single_obje.Slot_List = 'Enable'
                elif checkbox_name == 'Pool_Active':
                    Single_obje.Pool_Active = 'Enable'
                elif checkbox_name == 'Pool_delete':
                    Single_obje.Pool_delete = 'Enable'
                elif checkbox_name == 'Pool_create':
                    Single_obje.Pool_create = 'Enable'
                elif checkbox_name == 'Pool_Upload':
                    Single_obje.Pool_Upload = 'Enable'
                
            else:
                if checkbox_name == 'Keys_Create':
                    Single_obje.Keys_Create = 'Disable'
                elif checkbox_name == 'Valid_Load_Request':
                    Single_obje.Valid_Load_Request = 'Disable'
                elif checkbox_name == 'CA_CRT':
                    Single_obje.CA_CRT = 'Disable'
                elif checkbox_name == 'CRT_Delete_Client':
                    Single_obje.CRT_Delete_Client = 'Disable'
                elif checkbox_name == 'crt_load_client':
                    Single_obje.crt_load_client = 'Disable'
                elif checkbox_name == 'CSR_HSM_CRT_Request':
                    Single_obje.CSR_HSM_CRT_Request = 'Disable'
                elif checkbox_name == 'CA_CRT_Delete':
                    Single_obje.CA_CRT_Delete = 'Disable'
                elif checkbox_name == 'Keys_Delete':
                    Single_obje.Keys_Delete = 'Disable'
                elif checkbox_name == 'Slot_delete':
                    Single_obje.Slot_delete = 'Disable'
                elif checkbox_name == 'hsm_slot_update':
                    Single_obje.hsm_slot_update = 'Disable'
                elif checkbox_name == 'Slot_List':
                    Single_obje.Slot_List = 'Disable'
                elif checkbox_name == 'Pool_Active':
                    Single_obje.Pool_Active = 'Disable'
                elif checkbox_name == 'Pool_delete':
                    Single_obje.Pool_delete = 'Disable'
                elif checkbox_name == 'Pool_create':
                    Single_obje.Pool_create = 'Disable'
                elif checkbox_name == 'Pool_Upload':
                    Single_obje.Pool_Upload = 'Disable'
            Single_obje.save()
    return redirect('Users_All')

@login_required
@user_type_required(user_types=['System_User','Operator_User'])
def UserTypeUpdate(request, id):
    print(id)
    if request.method == 'POST':
        UserType = request.POST['UserType']
        UserTypeModel = UserProfile.objects.get(id=id)
        UserTypeModel.USerType = UserType
        UserTypeModel.save()
    return redirect('Users_All')

@login_required
def Rules_Upload(request, str_name):
    if request.method == 'POST':
        hsm_certificate_name = request.POST['hsm_certificate_name']
        certificate_stay_days = request.POST['certificate_stay_days']
        hsm_certificate_user_name = request.POST['certificate_stay_days']
        print(certificate_stay_days)
        return redirect('Rules_view')
    else:
        return redirect('Rules_view')
    

@login_required
def HSM_To_Certificate(request, slot_label, slot_id, certificate_name):
    CertType = "Certificate"
    PIN_Encrypt = slotlist.objects.filter(TokenName=slot_label).values_list('UserPIN', flat=True).first()
    Action = "Decrypt"
    result = Slot_PIN_ENC_DEC(Action,PIN_Encrypt)
    json_string = json.dumps(result)
    loaded_data = json.loads(json_string)
    Token_PIN = loaded_data['Message:']['Decrypt Data: ']
    result = Obje_Remove_Request(slot_id,Token_PIN,CertType,certificate_name)
    Remove_Message = result['Message: ']
    messages.success(request, Remove_Message)
    return redirect('HSM_Certificate')

@login_required
@user_type_required(user_types=['System_User','Operator_User'])
def Dashboard(request):
    HSM_Name = hsmpool.objects.filter(MultiTenantName=TenantName, HSM_Status='active')
    ### Tarihi Yaklaşanlar ###
    obje = []
    S_List = slotlist.objects.all()
    for Slot in S_List:
        TokenName = Slot.TokenName
        Token_ID = FindID(TokenName)
        if Token_ID['Message: '] == 'Token not found':
            pass
        else:
            Slot_ID = Token_ID['Message: ']['slot_id']
            PIN_Encrypt = slotlist.objects.filter(TokenName=TokenName).values_list('UserPIN', flat=True).first()
            Action = "Decrypt"
            result = Slot_PIN_ENC_DEC(Action,PIN_Encrypt)
            json_string = json.dumps(result)
            loaded_data = json.loads(json_string)
            Token_PIN = loaded_data['Message:']['Decrypt Data: ']
            cert_all = Certificate_ALL(Slot_ID,Token_PIN)
            for cert in cert_all:
                obje.append(cert)
    sorted_data = sorted(obje, key=lambda x: x['Last_Date'])
    sorted_data.reverse()
    sorted_data = sorted_data[0:5]

    #### Expried olanlar
    stay_obje = []
    S_List = slotlist.objects.all()

    # Bugünün tarihini al
    today_date = datetime.now().date()

    for Slot in S_List:
        TokenName = Slot.TokenName
        Token_ID = FindID(TokenName)

        if Token_ID['Message: '] == 'Token not found':
            pass
        else:
            Slot_ID = Token_ID['Message: ']['slot_id']
            PIN_Encrypt = slotlist.objects.filter(TokenName=TokenName).values_list('UserPIN', flat=True).first()
            Action = "Decrypt"
            result = Slot_PIN_ENC_DEC(Action, PIN_Encrypt)
            json_string = json.dumps(result)
            loaded_data = json.loads(json_string)
            Token_PIN = loaded_data['Message:']['Decrypt Data: ']
            cert_all = Certificate_ALL(Slot_ID, Token_PIN)

            for cert in cert_all:
                # Last_Date alanını doğru tarih formatına çevir
                cert['Last_Date'] = datetime.strptime(cert['Last_Date'], '%d/%m/%Y %H:%M:%S').date()
                stay_obje.append(cert)

    # Geçmiş tarihli sertifikaları bul
    expired_certs = [cert for cert in stay_obje if cert['Last_Date'] < today_date]
    print(expired_certs)
    # Orijinal diziden geçmiş tarihli olanları çıkar
    stay_obje = [cert for cert in stay_obje if cert['Last_Date'] >= today_date]
    print(stay_obje)
    # Kalan sertifikaları tarihe göre sırala ve en son 5 tanesini al
    sorted_data_deneme = sorted(stay_obje, key=lambda x: x['Last_Date'], reverse=True)[:5]
    print(sorted_data_deneme)
    # Eğer geçmiş tarihli sertifikalar varsa, işlemleri gerçekleştir
    if expired_certs:
        # Burada geçmiş tarihli sertifikaları başka bir işlem yapabilirsiniz
        # Örneğin, silmek, arşivlemek vb.
        pass
    ### New Created 
    # certificates ve client_crt modellerinden sorgu kümesini al
    certificates_query = certificates.objects.filter(
        Q(Data_Start__lte=date.today()) & Q(Data_End__gte=date.today())
    ).order_by('Data_Start')[:10]

    client_crt_query = client_crt.objects.filter(
        Q(Data_Start__lte=date.today()) & Q(Data_End__gte=date.today())
    ).order_by('Data_Start')[:10]

    # İki queryset'i birleştir
    combined_data = list(certificates_query) + list(client_crt_query)

    # Tarih sırasına göre sırala
    combined_data.sort(key=lambda x: x.Data_Start)
    # Sadece ilk 10 veriyi al
    combined_data = combined_data[:10]
    UserType = UserProfile.objects.filter(user=request.user.id).values_list('USerType', flat=True).first()

    ### Health Check

    PKI_API = PKI_API_Check()
    return render(request, 'Dashboard.html', {'UserType':UserType, 'HSM_Name':HSM_Name,  'sorted_data':sorted_data,'combined_data':combined_data, 'expired_certs':expired_certs,'PKI_API':PKI_API})

@login_required
@user_type_required(user_types=['System_User','Operator_User'])
def Single_Backup_CSV(request, filename):
    print(filename)
    dosya_adı, uzantı = os.path.splitext(filename)
    print(dosya_adı)
    print(uzantı)
    if uzantı == '.csv':
        ### CSV veri oluşturma
        csv_file_path = f'/opt/BackupLog/{filename}'
        veri = []
        # CSV dosyasını açma ve okuma
        with open(csv_file_path, mode='r', encoding='utf-8') as dosya:
            csv_okuyucu = csv.DictReader(dosya)
            for satir in csv_okuyucu:
                veri.append(satir)
        print(veri)
    elif uzantı == '.enc':
        ID = 1
        PIN = "1111"
        KeyName = "Log_File_Encrypt"

        result = FileDecrypt(ID,PIN,KeyName,filename)
        print(result)
        filename = dosya_adı
        ### CSV veri oluşturma
        csv_file_path = f'/opt/BackupLog/{filename}'
        veri = []
        # CSV dosyasını açma ve okuma
        with open(csv_file_path, mode='r', encoding='utf-8') as dosya:
            csv_okuyucu = csv.DictReader(dosya)
            for satir in csv_okuyucu:
                veri.append(satir)
        print(veri)
        os.remove(csv_file_path)
    else:
        veri = []
    
    Logs_File = get_file_info()
    UserType = UserProfile.objects.filter(user=request.user.id).values_list('USerType', flat=True).first()
    return render(request, 'Logs_BackupCSV.html',{'UserType':UserType, 'Logs_File':Logs_File, 'data':veri})



@login_required
@require_POST
def export_to_csv(request):
    # Formdan alınan veri
    data = request.POST.get('data')

    # Yanıtı oluştur
    response = HttpResponse(
        content_type='text/csv',
        headers={'Content-Disposition': 'attachment; filename="exported_data.csv"'},
    )

    writer = csv.writer(response)

    # Verileri CSV'ye yaz
    for item in eval(data):
        writer.writerow(item.values())

    return response