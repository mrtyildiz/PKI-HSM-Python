from ldap3 import Server, Connection, MODIFY_ADD, MODIFY_REPLACE, HASHED_SHA, HASHED_MD5, MODIFY_DELETE
import base64
from ldap3 import Server, Connection, SUBTREE

def LdapUserCreate(username,password):

    # LDAP Sunucu Bilgileri
    ldap_server = Server('ldap://172.16.0.10:389')
    ldap_user = 'cn=admin,dc=Procenne,dc=com'
    ldap_password = 'admin_password'
    # Kullanıcı Bilgileri
    # username = 'user2'
    # password = 'user2password'
    base_dn = 'ou=People,dc=Procenne,dc=com'
    # Bağlantı Oluştur
    connection = Connection(ldap_server, user=ldap_user, password=ldap_password, auto_bind=True)
    # Kullanıcı Eklemek İçin LDIF Oluştur
    user_dn = f'cn={username},{base_dn}'
    user_password_encoded = base64.b64encode(password.encode('utf-8')).decode('utf-8')
    user_ldif = {
        'objectClass': ['top', 'person', 'organizationalPerson', 'inetOrgPerson'],
        'cn': username,
        'sn': username,
        'givenName': username,
        'uid': username,
        'userPassword': [f'{{MD5}}{user_password_encoded}']
    }
    # Kullanıcıyı Eklemek İçin LDAP Komutu Gönder
    connection.add(user_dn, attributes=user_ldif)
    #Bağlantıyı Kapat
    connection.unbind()




# LDAP Sunucu Bilgileri
ldap_server = Server('ldap://172.16.0.11:389')
ldap_user = 'cn=admin,dc=Procenne,dc=com'
ldap_password = 'admin_password'
base_dn = 'ou=People,dc=Procenne,dc=com'

# Bağlantı Oluştur
connection = Connection(ldap_server, user=ldap_user, password=ldap_password, auto_bind=True)

# Kullanıcıları Listele
search_filter = '(objectClass=inetOrgPerson)'
attributes = ['cn', 'sn', 'givenName', 'uid']

connection.search(search_base=base_dn, search_filter=search_filter, search_scope=SUBTREE, attributes=attributes)

for entry in connection.entries:
    print(f"CN: {entry.cn.value}, SN: {entry.sn.value}, Given Name: {entry.givenName.value}, UID: {entry.uid.value}")

# Bağlantıyı Kapat
connection.unbind()
