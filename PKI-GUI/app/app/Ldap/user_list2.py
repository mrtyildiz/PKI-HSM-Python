from ldap3 import Server, Connection, SUBTREE, ALL
import os
Ldap_HostName = os.environ.get("Ldap_HostName")
LdapDomainName = os.environ.get("LdapDomainName")
LdapAdminPassword = os.environ.get("LdapAdminPassword")
# LDAP sunucu bilgileri
ldap_server_ip = '172.16.0.11'
ldap_server_port = 389  # LDAP standard portu

# Bağlantı oluştur
server = Server('ldap://{}:{}'.format(Ldap_HostName, ldap_server_port))
conn = Connection(server, user=LdapDomainName, password=LdapAdminPassword)

# Bağlan
if not conn.bind():
    print('Bağlantı başarısız: {}'.format(conn.result))
else:
    print('Bağlantı başarılı')

    # Kullanıcıları listele
    search_base = 'ou=users,dc=procenne,dc=com'
    search_filter = '(objectClass=inetOrgPerson)'
    conn.search(search_base, search_filter, SUBTREE, attributes='*')  # Burada 'ALL' yerine '*'

    for entry in conn.entries:
        print('DN: {}'.format(entry.entry_dn))
        for attribute in entry.entry_attributes:
            print('  {}: {}'.format(attribute, entry[attribute]))

    # Bağlantıyı kapat
    conn.unbind()
