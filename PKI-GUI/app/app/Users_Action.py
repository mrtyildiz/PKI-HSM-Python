from ldap3 import Server, Connection, MODIFY_ADD, ALL
import os
import ldap3
from ldap3.core.exceptions import LDAPException
from django.contrib.auth import get_user_model
from ldap3 import Server, Connection
from .models import UserProfile
import json
from .OTPUsers import *

Ldap_HostName = os.environ.get("Ldap_HostName")
LdapDomainName = os.environ.get("LdapDomainName")
LdapAdminPassword = os.environ.get("LdapAdminPassword")
def create_ldap_user(username, full_name, password):
    # LDAP sunucu bilgileri
    ldap_server_ip = Ldap_HostName   # environment
    ldap_server_port = 389  # LDAP standard portu # environment
    #ldap_admin_dn = 'cn=admin,dc=procenne,dc=com' # environment
    ldap_admin_dn = LdapDomainName
    ldap_admin_password = LdapAdminPassword # environment

    # Kullanıcı bilgileri
    user_dn = f'uid={username},ou=users,dc=procenne,dc=com'
    user_attributes = {
        'objectClass': ['top', 'person', 'organizationalPerson', 'inetOrgPerson'],
        'uid': username,
        'cn': full_name,
        'sn': 'User',
        'givenName': username,
        'userPassword': password
    }

    # Bağlantı oluştur
    server = Server('ldap://{}:{}'.format(ldap_server_ip, ldap_server_port))
    conn = Connection(server, user=ldap_admin_dn, password=ldap_admin_password)

    try:
        # Bağlan
        if not conn.bind():
            raise Exception('LDAP bağlantısı başarısız: {}'.format(conn.result))

        # Kullanıcıyı oluştur
        conn.add(user_dn, attributes=user_attributes)

        print('Kullanıcı başarıyla oluşturuldu.')
        result = "Kullanıcı başarıyla oluşturuldu."

    except Exception as e:
        print('LDAP Hatası:', e)
        result = "LDAP Hatası"
    finally:
        # Bağlantıyı kapat
        conn.unbind()
    return result

def custom_ldap_authenticate(username, password):
    # LDAP sunucu bilgileri
    ldap_server_ip = Ldap_HostName
    ldap_server_port = 389
    ldap_admin_dn = LdapDomainName
    ldap_admin_password = LdapAdminPassword
    search_base = 'ou=users,dc=procenne,dc=com'
    search_filter = '(uid={})'.format(username)

    # Bağlantı oluştur
    server = ldap3.Server('ldap://{}:{}'.format(ldap_server_ip, ldap_server_port))
    conn = ldap3.Connection(server, user=ldap_admin_dn, password=ldap_admin_password)

    try:
        # Bağlan
        if not conn.bind():
            raise LDAPException('LDAP bağlantısı başarısız: {}'.format(conn.result))

        # Kullanıcıyı ara
        conn.search(search_base, search_filter, ldap3.SUBTREE)

        # Kullanıcı bulunamazsa
        if not conn.entries:
            raise LDAPException('Kullanıcı bulunamadı.')

        # Kullanıcı adı ve şifre ile kimlik doğrulama yap
        user_dn = conn.entries[0].entry_dn
        conn = ldap3.Connection(server, user=user_dn, password=password)

        if not conn.bind():
            raise LDAPException('LDAP kimlik doğrulama başarısız: {}'.format(conn.result))
        
        # LDAP kimlik doğrulama başarılı ise, Django User modelini kontrol et
        User = get_user_model()
        try:
            user = User.objects.get(username=username)
            
        except User.DoesNotExist:
            # Kullanıcı veritabanında bulunmazsa, yeni bir kullanıcı oluştur
            user = User.objects.create_user(username, email='', password='')
            UserQR = QRCreate(username)
            json_data = json.dumps(UserQR)
            parsed_data = json.loads(json_data)
            Profil_Create = UserProfile.objects.create(user=user, UserType="Ldap", TwoFactor="Disable",OTP_Value=parsed_data['user_secret'],QR_Path=parsed_data['IMG_URL'])
            Profil_Create.save()
        return user

    except LDAPException as e:
        print('LDAP Hatası:', e)
        return None

    finally:
        # Bağlantıyı kapat
        conn.unbind()

