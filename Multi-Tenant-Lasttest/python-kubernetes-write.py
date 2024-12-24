import os

Tanent_Name = 'tanent-23'
Namespace_File = '0-New-Namespace.yaml'
HSM_Deployment_File = '1-hsm-deployment.yaml'
HSM_Service_File = '1-hsm-service.yaml'
PKI_API_Deployment_File = '2-pki-api-deployment.yaml'
PKI_API_Service_File = '2-pki-api-service.yaml'
Rabbitmq_Deployment_File = '3-rabbitmq-deployment.yaml'
Rabbitmq_Service_File = '3-rabbitmq-service.yaml'
Postgresql_Deployment_File = '4-postgres-deployment.yaml'
Postgresql_Service_File = '4-postgres-service.yaml'
Postgresql_PV_File = '4-postgres-pv.yaml'
PKI_GUI_Deployment_File = '5-app-gui-deployment.yaml'
PKI_GUI_Service_File = '5-app-gui-service.yaml'
PKI_GUI_PV_File = '5-gui-app-pv.yaml'
Ldap_Deployment_File = '6-ldap-server-deployment.yaml'
Ldap_Service_File = '6-ldap-server-service.yaml'
PKI_FTP_Deployment_File = '7-pki-ftp-deployment.yaml'
PKI_FTP_Service_File = '7-pki-ftp-service.yaml'
PKI_Mail_Deployment_File = '8-pki-mail-deployment.yaml'
PKI_Mail_Service_File = '8-pki-mail-service.yaml'
PKI_Alarm_Deployment_File = '9-pki-alarm-deployment.yaml'
PKI_Alarm_Service_File = '9-pki-alarm-service.yaml'

New_Namespace = f'''apiVersion: v1
kind: Namespace
metadata:
  name: {Tanent_Name}
'''
with open(Namespace_File, 'w') as dosya:
    dosya.write(New_Namespace)

HSM_Deployment = f'''apiVersion: apps/v1
kind: Deployment
metadata:
  name: hsm
  namespace: {Tanent_Name}  # Namespace belirtilmiş
spec:
  replicas: 2
  selector:
    matchLabels:
      app: hsm
  template:
    metadata:
      labels:
        app: hsm
    spec:
      containers:
      - name: hsm
        image: pkihsm-twoslot:5.0
        ports:
        - containerPort: 5000
'''

with open(HSM_Deployment_File, 'w') as dosya:
    dosya.write(HSM_Deployment)

HSM_Service = f'''apiVersion: v1
kind: Service
metadata:
  name: hsm-service
  namespace: {Tanent_Name}  # Namespace belirtilmiş
spec:
  selector:
    app: hsm
  ports:
    - protocol: TCP
      port: 5000
      targetPort: 5000
  type: NodePort
'''
with open(HSM_Service_File, 'w') as dosya:
    dosya.write(HSM_Service)

PKI_API_Deployment = f'''apiVersion: v1
kind: Pod
metadata:
  name: pki-api
  namespace: {Tanent_Name}  # Namespace belirtilmiş
spec:
  containers:
  - name: pki-api
    image: pki_hsm_all:1.0
    command: ["sleep", "36000"]
    env:
    - name: PYKCS11LIB
      value: /lib64/libprocryptoki.so
    - name: Rabbit_Host
      value: rabbitmq-service
    - name: RabbitUser
      value: myuser
    - name: RabbitPassword
      value: mypassword
    - name: RABBITMQ_HOST
      value: pki_rabbitmq
    - name: TZ
      value: "Europe/Istanbul"
    - name: API_Slot
      value: IoaqNDIk1Z9Lx8XL3t13PuoovWvum83U
    - name: Slot_PIN
      value: gAAAAABlUhkSu9zmmOqy_Q8CQchXhGyhb0aPYcJ1tXO4oeHYESw-hxZjbbwTWeDrvCwMVO9xE13H7TJxNIV3JEDYfKyG_s0sEg==
    - name: Slot_ID
      value: "1"
    - name: Slot_Key_Name
      value: Slot_Encrypt_AES
    ports:
    - containerPort: 8000
    volumeMounts:
    - name: app-volume
      mountPath: /app/
    - name: config-volume
      mountPath: /opt/procrypt/km3000/config/
    - name: logs-volume
      mountPath: /opt/BackupLog/
  volumes:
  - name: app-volume
    hostPath:
      path: /MultiTanent/PKI-APP/app/
  - name: config-volume
    hostPath:
      path: /MultiTanent/PKI-APP/config/
  - name: logs-volume
    hostPath:
      path: /MultiTanent/Backup_Logs/
'''

with open(PKI_API_Deployment_File, 'w') as dosya:
    dosya.write(PKI_API_Deployment)

PKI_API_Service = f'''apiVersion: v1
kind: Service
metadata:
  name: pki-api-http
  namespace: {Tanent_Name}  # Namespace belirtilmiş
spec:
  selector:
    app: pki-api
  ports:
  - protocol: TCP
    port: 8000
    targetPort: 8000
'''

with open(PKI_API_Service_File, 'w') as dosya:
    dosya.write(PKI_API_Service)

Rabbitmq_Deployment = f'''apiVersion: apps/v1
kind: Deployment
metadata:
  name: rabbitmq-deployment
  namespace: {Tanent_Name}
spec:
  replicas: 1
  selector:
    matchLabels:
      app: rabbitmq
  template:
    metadata:
      labels:
        app: rabbitmq
    spec:
      containers:
      - name: rabbitmq-container
        image: rabbitmq:management
        ports:
        - containerPort: 5672
        - containerPort: 15672
        env:
        - name: RABBITMQ_DEFAULT_USER
          valueFrom:
            secretKeyRef:
              name: rabbitmq-secret
              key: RABBITMQ_DEFAULT_USER
        - name: RABBITMQ_DEFAULT_PASS
          valueFrom:
            secretKeyRef:
              name: rabbitmq-secret
              key: RABBITMQ_DEFAULT_PASS
        - name: TZ
          value: "Europe/Istanbul"
        volumeMounts:
        - name: rabbitmq-data
          mountPath: /var/lib/rabbitmq
      volumes:
      - name: rabbitmq-data
        emptyDir: '''+'{'+'}'


with open(Rabbitmq_Deployment_File, 'w') as dosya:
    dosya.write(Rabbitmq_Deployment)

Rabbitmq_Service = f'''apiVersion: v1
kind: Service
metadata:
  name: rabbitmq-service
  namespace: {Tanent_Name}  # Namespace belirtilmiş
spec:
  selector:
    app: rabbitmq
  ports:
  - name: rabbitmq
    protocol: TCP
    port: 5672
    targetPort: 5672
  - name: rabbitmq-management
    protocol: TCP
    port: 15672
    targetPort: 15672
  type: ClusterIP
'''
with open(Rabbitmq_Service_File, 'w') as dosya:
    dosya.write(Rabbitmq_Service)

Postgresql_Deployment = f'''apiVersion: apps/v1
kind: Deployment
metadata:
  name: postgres-deployment
  namespace: {Tanent_Name}  # Namespace belirtilmiş
spec:
  replicas: 1
  selector:
    matchLabels:
      app: postgres
  template:
    metadata:
      labels:
        app: postgres
    spec:
      containers:
      - name: postgres-container
        image: postgres:latest
        env:
        - name: POSTGRES_USER
          value: "postgres"
        - name: POSTGRES_PASSWORD
          value: "postgres"
        - name: POSTGRES_DB
          value: "postgres"
        - name: TZ
          value: "Europe/Istanbul"
        ports:
        - containerPort: 5432
        volumeMounts:
        - name: postgres-data
          mountPath: /var/lib/postgresql/data
      volumes:
      - name: postgres-data
        hostPath:
          path: /MultiTanent/Postgresql/  # Bu yolu uygun şekilde güncelleyin
'''
with open(Postgresql_Deployment_File, 'w') as dosya:
    dosya.write(Postgresql_Deployment)


Postgresql_Service = f'''apiVersion: v1
kind: Service
metadata:
  name: postgres-service
  namespace: {Tanent_Name}  # Namespace belirtilmiş
spec:
  selector:
    app: postgres
  ports:
  - protocol: TCP
    port: 5432
    targetPort: 5432
'''
with open(Postgresql_Service_File, 'w') as dosya:
    dosya.write(Postgresql_Service)

Postgresql_PV = f'''apiVersion: v1
kind: PersistentVolume
metadata:
  name: postgres-pv
  namespace: {Tanent_Name}
spec:
  capacity:
    storage: 1Gi
  accessModes:
    - ReadWriteOnce
  hostPath:
    path: /MultiTanent/Postgresql/  # Bu yolu uygun şekilde güncelleyin
'''

with open(Postgresql_PV_File, 'w') as dosya:
    dosya.write(Postgresql_PV)


PKI_GUI_Deployment = f'''apiVersion: apps/v1
kind: Deployment
metadata:
  name: app-gui-deployment
  namespace: {Tanent_Name}  # Namespace belirtilmiş
spec:
  replicas: 1
  selector:
    matchLabels:
      app: app-gui
  template:
    metadata:
      labels:
        app: app-gui
    spec:
      containers:
      - name: app-gui-container
        image: pki-gui:2.0
        env:
        - name: NAMESPACE
          value: "{Tanent_Name}" # değişkeni tanımla
        - name: Postgresql_DB
          value: "pki_gui_db"
        - name: Postgresql_User
          value: "postgres"
        - name: Postgresql_Password
          value: "postgres"
        - name: Postgresql_IP
          value: "rabbitmq-service"
        - name: Postgresql_Port
          value: "5432"
        - name: API_URL
          value: "http://app-pki:8000/"
        - name: TZ
          value: "Europe/Istanbul"
        - name: API_Slot
          value: "IoaqNDIk1Z9Lx8XL3t13PuoovWvum83U"
        - name: Rabbit_Host
          value: "rabbitmq-service"
        - name: RabbitUser
          value: "myuser"
        - name: RabbitPassword
          value: "mypassword"
        - name: Ldap_HostName
          value: "ldap-server-service"
        - name: LdapDomainName
          value: "cn=admin,dc=procenne,dc=com"
        - name: LdapAdminPassword
          value: "admin"
        ports:
        - containerPort: 8000
        command: ["python3", "manage.py", "runserver", "0.0.0.0:8000"]
        volumeMounts:
        - name: gui-app-volume
          mountPath: /app
        - name: gui-app-api-crt
          mountPath: /app/app/CRT
        - name: gui-app-api-public
          mountPath: /app/app/Public
        - name: gui-app-api-csr
          mountPath: /app/app/CSR
        - name: gui-app-backup
          mountPath: /opt/BackupLog
      volumes:
      - name: gui-app-volume
        hostPath:
          path: /MultiTanent/PKI-GUI/app/  # Bu yolu uygun şekilde güncelleyin
      - name: gui-app-api-crt
        hostPath:
          path: /MultiTanent/PKI-APP/app/CRT
      - name: gui-app-api-public
        hostPath:
          path: /MultiTanent/PKI-APP/app/Public
      - name: gui-app-api-csr
        hostPath:
          path: /MultiTanent/PKI-APP/app/CSR
      - name: gui-app-backup
        hostPath:
          path: /MultiTanent/FTP-Server/data
'''


with open(PKI_GUI_Deployment_File, 'w') as dosya:
    dosya.write(PKI_GUI_Deployment)


PKI_GUI_Service = f'''apiVersion: v1
kind: Service
metadata:
  name: app-gui-service
  namespace: {Tanent_Name}  # Namespace belirtilmiş
spec:
  selector:
    app: app-gui
  ports:
  - protocol: TCP
    port: 9000
    targetPort: 8000
'''
with open(PKI_GUI_Service_File, 'w') as dosya:
    dosya.write(PKI_GUI_Service)

PKI_GUI_PV = f'''apiVersion: v1
kind: PersistentVolume
metadata:
  name: gui-app-pv
  namespace: {Tanent_Name}  # Namespace belirtilmiş
spec:
  capacity:
    storage: 1Gi
  accessModes:
    - ReadWriteOnce
  hostPath:
    path: /pki-api/PKI-GUI/app/  # Bu yolu uygun şekilde güncelleyin
'''

with open(PKI_GUI_PV_File, 'w') as dosya:
    dosya.write(PKI_GUI_PV)

Ldap_Deployment = f'''apiVersion: apps/v1
kind: Deployment
metadata:
  name: ldap-server-deployment
  namespace: {Tanent_Name}  # Namespace belirtilmiş
spec:
  replicas: 1
  selector:
    matchLabels:
      app: ldap-server
  template:
    metadata:
      labels:
        app: ldap-server
    spec:
      containers:
      - name: ldap-server
        image: pkildap:1.0
        env:
        - name: LDAP_DOMAIN
          value: "procenne.com"
        - name: LDAP_ADMIN_PASSWORD
          value: "admin"
        - name: LDAP_TLS_VERIFY_CLIENT
          value: "never"
        - name: LDAP_TLS_CRT_FILENAME
          value: "ldap.crt"
        - name: LDAP_TLS_KEY_FILENAME
          value: "ldap.key"
        ports:
        - containerPort: 389
        - containerPort: 636
'''
with open(Ldap_Deployment_File, 'w') as dosya:
    dosya.write(Ldap_Deployment)


Ldap_Service = f'''apiVersion: v1
kind: Service
metadata:
  name: ldap-server-service
  namespace: {Tanent_Name}  # Namespace belirtilmiş
spec:
  selector:
    app: ldap-server
  ports:
  - name: ldap-port
    protocol: TCP
    port: 389
    targetPort: 389
  - name: ldaps-port
    protocol: TCP
    port: 636
    targetPort: 636
'''

with open(Ldap_Service_File, 'w') as dosya:
    dosya.write(Ldap_Service)

PKI_FTP_Deployment = f'''apiVersion: apps/v1
kind: Deployment
metadata:
  name: pki-ftp-deployment
  namespace: {Tanent_Name}  # Namespace belirtilmiş
spec:
  replicas: 1
  selector:
    matchLabels:
      app: pki-ftp
  template:
    metadata:
      labels:
        app: pki-ftp
    spec:
      containers:
      - name: pki-ftp-container
        image: pkiftpserver:1.0
        ports:
        - containerPort: 21
        volumeMounts:
        - name: ftp-data-volume
          mountPath: /app/LogBackup
        command: ["python3", "-m", "python_ftp_server", "--ip", "0.0.0.0", "--port", "21", "-u", "FTPAdmin", "-p", "1q2w3e4r5t*", "-d", "/app/LogBackup"]
      volumes:
      - name: ftp-data-volume
        hostPath:
          path: /MultiTanent/FTP-Server/data/  # Bu yolu uygun şekilde güncelleyin
'''

with open(PKI_FTP_Deployment_File, 'w') as dosya:
    dosya.write(PKI_FTP_Deployment)

PKI_FTP_Service = f'''apiVersion: v1
kind: Service
metadata:
  name: pki-ftp-service
  namespace: {Tanent_Name}  # Namespace belirtilmiş
spec:
  selector:
    app: pki-ftp
  ports:
  - protocol: TCP
    port: 21
    targetPort: 21
'''

with open(PKI_FTP_Service_File, 'w') as dosya:
    dosya.write(PKI_FTP_Service)

PKI_Mail_Deployment = f'''apiVersion: apps/v1
kind: Deployment
metadata:
  name: pki-mail-deployment
  namespace: {Tanent_Name}  # Namespace belirtilmiş
spec:
  replicas: 1
  selector:
    matchLabels:
      app: pki-mail
  template:
    metadata:
      labels:
        app: pki-mail
    spec:
      containers:
      - name: pki-mail-container
        image: pkimail:1.0
        ports:
        - containerPort: 1025
        - containerPort: 8025
'''

with open(PKI_Mail_Deployment_File, 'w') as dosya:
    dosya.write(PKI_Mail_Deployment)

PKI_Mail_Service = f'''apiVersion: v1
kind: Service
metadata:
  name: pki-mail-service
  namespace: {Tanent_Name}  # Namespace belirtilmiş
spec:
  selector:
    app: pki-mail
  ports:
  - name: smtp
    protocol: TCP
    port: 1025
    targetPort: 1025
  - name: webui
    protocol: TCP
    port: 8025
    targetPort: 8025
'''
with open(PKI_Mail_Service_File, 'w') as dosya:
    dosya.write(PKI_Mail_Service)

  
PKI_Alarm_Deployment = f'''apiVersion: apps/v1
kind: Deployment
metadata:
  name: pki-alarm-deployment
  namespace: {Tanent_Name}  # Namespace belirtilmiş
spec:
  replicas: 1
  selector:
    matchLabels:
      app: pki-alarm
  template:
    metadata:
      labels:
        app: pki-alarm
    spec:
      containers:
      - name: pki-alarm-container
        image: pkialarm:2.0
        env:
        - name: MailHostName
          value: "pki-mail-service"
        - name: Postgresql_DB
          value: "pki_gui_db"
        - name: Postgresql_User
          value: "postgres"
        - name: Postgresql_Password
          value: "postgres"
        - name: Postgresql_IP
          value: "postgres"
        - name: Postgresql_Port
          value: "5432"
        ports:
        - containerPort: 8000
        volumeMounts:
        - name: pki-alarm-volume
          mountPath: /app
        - name: pki-gui-volume
          mountPath: /app/app/models.py
        command: ["python3", "manage.py","runserver"]
      volumes:
      - name: pki-alarm-volume
        hostPath:
          path: /MultiTanent/PKI-Alarm/app  # Bu yolu uygun şekilde güncelleyin
      - name: pki-gui-volume
        hostPath:
          path: /MultiTanent/PKI-GUI/app/app/models.py  # Bu yolu uygun şekilde güncelleyin
'''
with open(PKI_Alarm_Deployment_File, 'w') as dosya:
    dosya.write(PKI_Alarm_Deployment)

PKI_Alarm_Service = f'''apiVersion: v1
kind: Service
metadata:
  name: pki-alarm-service
  namespace: {Tanent_Name}  # Namespace belirtilmiş
spec:
  selector:
    app: pki-alarm
  ports:
  - protocol: TCP
    port: 9090
    targetPort: 8000
'''
with open(PKI_Alarm_Service_File, 'w') as dosya:
    dosya.write(PKI_Alarm_Service)