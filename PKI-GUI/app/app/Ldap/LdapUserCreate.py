from ldap3 import Server, Connection
import os
def create_ldap_user(username, full_name, password):
    # LDAP sunucu bilgileri
    ldap_server_ip = os.environ.get("Ldap_HostName")   # environment
    ldap_server_port = 389  # LDAP standard portu # environment
    ldap_admin_dn = os.environ.get("LdapDomainName") # environment
    ldap_admin_password = os.environ.get("LdapAdminPassword") # environment

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

    except Exception as e:
        print('LDAP Hatası:', e)

    finally:
        # Bağlantıyı kapat
        conn.unbind()

# Kullanıcıyı oluşturmak için fonksiyonu çağır
#create_ldap_user('newuser6', 'New User', '#newuserpassword')
