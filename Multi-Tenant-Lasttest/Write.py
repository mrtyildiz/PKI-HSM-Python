import os

#### New Create Namespace
Tanent_Name = 'tanent-1'
Namespace_File = '0-New-Namespace.yaml'

New_Namespace = f'''apiVersion: v1
kind: Namespace
metadata:
  name: {Tanent_Name}

'''
with open(Namespace_File, 'w') as dosya:
    dosya.write(New_Namespace)

HSM_Deployment_File = '1-hsm-deployment.yaml'

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


HSM_Service_File = '1-hsm-service.yaml'

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


PKI_API_Deployment_File = '2-pki-api-deployment.yaml'

PKI_API_Deployment = f'''apiVersion: v1
kind: Pod
metadata:
  name: pki-api
  namespace: {Tanent_Name}
spec:
  containers:
  - name: pki-api
    image: pki_hsm_all:1.0
    command: ["python3", "app.py"]
    env:
    - name: PYKCS11LIB
      value: /lib64/libprocryptoki.so
    - name: Slot_PIN
      value: gAAAAABlUhkSu9zmmOqy_Q8CQchXhGyhb0aPYcJ1tXO4oeHYESw-hxZjbbwTWeDrvCwMVO9xE13H7TJxNIV3JEDYfKyG_s0sEg==
    - name: Rabbit_Host
      value: rabbitmq-service
    - name: RabbitUser
      valueFrom:
        secretKeyRef:
          name: pki-api-secrets
          key: RabbitUser
    - name: RabbitPassword
      valueFrom:
        secretKeyRef:
          name: pki-api-secrets
          key: RabbitPassword
    - name: RABBITMQ_HOST
      valueFrom:
        secretKeyRef:
          name: pki-api-secrets
          key: RABBITMQ_HOST
    - name: Slot_ID
      valueFrom:
        secretKeyRef:
          name: pki-api-secrets
          key: Slot_ID
    - name: Slot_Key_Name
      valueFrom:
        secretKeyRef:
          name: pki-api-secrets
          key: Slot_Key_Name
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


PKI_API_Secret_File = '2-pki-api-secret.yaml'

PKI_API_Secret = f'''apiVersion: v1
kind: Secret
metadata:
  name: pki-api-secrets
  namespace: {Tanent_Name}
type: Opaque
data:
  PYKCS11LIB: /lib64/libprocryptoki.so
  RabbitUser: bXl1c2Vy   # Base64-encoded myuser
  RabbitPassword: bXlwYXNzd29yZA==   # Base64-encoded mypassword
  RABBITMQ_HOST: cGtpX3JhYmJpdG1x   # Base64-encoded pki_rabbitmq
  Slot_ID: MQ==   # Base64-encoded "1"
  Slot_Key_Name: U2xvdF9FbmNyeXB0X0FFUw==   # Base64-encoded Slot_Encrypt_AES

'''
with open(PKI_API_Secret_File, 'w') as dosya:
    dosya.write(PKI_API_Secret)

PKI_API_Service_File = '2-pki-api-service.yaml'

PKI_API_Service = f'''apiVersion: v1
kind: Service
metadata:
  name: pki-api-http
  namespace: {Tanent_Name}  # Namespace belirtilmi�
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

Rabbitmq_Deployment_File = '3-rabbitmq-deployment.yaml'

Rabbitmq_Deployment = f'''apiVersion: apps/v1
kind: Deployment
metadata:
  name: rabbitmq-deployment
  namespace: {Tanent_Name}  # Namespace belirtilmiş
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
          value: "myuser"
        - name: RABBITMQ_DEFAULT_PASS
          value: "mypassword"
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

Rabbitmq_Secret_File = '3-rabbitmq-secret.yaml'

Rabbitmq_Secret = f'''apiVersion: v1
kind: Secret
metadata:
  name: rabbitmq-secret
  namespace: tanent-1
type: Opaque
data:
  RABBITMQ_DEFAULT_USER: bXl1c2Vy   # Base64 encoded username
  RABBITMQ_DEFAULT_PASS: bXlwYXNzd29yZA==   # Base64 encoded password
'''


with open(Rabbitmq_Secret_File, 'w') as dosya:
    dosya.write(Rabbitmq_Secret)

Rabbitmq_Service_File = '3-rabbitmq-service.yaml'

Rabbitmq_Service = f'''apiVersion: v1
kind: Service
metadata:
  name: rabbitmq-service
  namespace: {Tanent_Name}  # Namespace belirtilmi�
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

Postgresql_Deployment_File = '4-postgres-deployment.yaml'

Postgresql_Deployment = f'''apiVersion: apps/v1
kind: Deployment
metadata:
  name: postgres-deployment
  namespace: {Tanent_Name}
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
          valueFrom:
            secretKeyRef:
              name: postgres-secret
              key: POSTGRES_USER
        - name: POSTGRES_PASSWORD
          valueFrom:
            secretKeyRef:
              name: postgres-secret
              key: POSTGRES_PASSWORD
        - name: POSTGRES_DB
          valueFrom:
            secretKeyRef:
              name: postgres-secret
              key: POSTGRES_DB
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
          path: /MultiTanent/Postgresql/
'''
with open(Postgresql_Deployment_File, 'w') as dosya:
    dosya.write(Postgresql_Deployment)

Postgresql_Secret_File = '4-postgres-secret.yaml'

Postgresql_Secret = f'''apiVersion: v1
kind: Secret
metadata:
  name: postgres-secret
  namespace: tanent-1
type: Opaque
data:
  POSTGRES_USER: cG9zdGdyZXM=  # Base64 encoded username 'postgres'
  POSTGRES_PASSWORD: cG9zdGdyZXM=  # Base64 encoded password 'postgres'
  POSTGRES_DB: cG9zdGdyZXM=  # Base64 encoded database name 'postgres'
'''
with open(Postgresql_Secret_File, 'w') as dosya:
    dosya.write(Postgresql_Secret)

Postgresql_Service_File = '4-postgres-service.yaml'

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

Postgresql_PV_File = '4-postgres-pv.yaml'

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
    path: /MultiTanent/Postgresql/  # Bu yolu uygun �ekilde g�ncelleyin
'''
with open(Postgresql_PV_File, 'w') as dosya:
    dosya.write(Postgresql_PV)

PKI_GUI_Deployment_File = '5-app-gui-deployment.yaml'

PKI_GUI_Deployment = f'''apiVersion: apps/v1
kind: Deployment
metadata:
  name: app-gui-deployment
  namespace: {Tanent_Name}
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
        image: pki-gui:3.0
        env:
        - name: NAMESPACE
          value: "{Tanent_Name}" # değişkeni tanımla
        - name: Postgresql_IP
          value: "postgres-service"
        - name: Postgresql_Port
          value: "5432"
        - name: Postgresql_DB
          value: "pki_gui_db"
        - name: API_URL
          value: "http://app-pki:8000/"
        - name: TZ
          value: "Europe/Istanbul"
        - name: API_Slot
          value: "IoaqNDIk1Z9Lx8XL3t13PuoovWvum83U"
        - name: Rabbit_Host
          value: "rabbitmq-service"
        - name: Ldap_HostName
          value: "ldap-server-service"
        - name: LdapDomainName
          value: "cn=admin,dc=procenne,dc=com"
          
        - name: Postgresql_User
          valueFrom:
            secretKeyRef:
              name: app-gui-secrets
              key: Postgresql_User
        - name: Postgresql_Password
          valueFrom:
            secretKeyRef:
              name: app-gui-secrets
              key: Postgresql_Password
        - name: RabbitUser
          valueFrom:
            secretKeyRef:
              name: app-gui-secrets
              key: RabbitUser
        - name: RabbitPassword
          valueFrom:
            secretKeyRef:
              name: app-gui-secrets
              key: RabbitPassword
        - name: LdapAdminPassword
          valueFrom:
            secretKeyRef:
              name: app-gui-secrets
              key: LdapAdminPassword
        ports:
        - containerPort: 8000
        command: ["sleep", "36000"]
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
          path: /MultiTanent/PKI-GUI/app/  # Update this path accordingly
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


PKI_GUI_Service_File = '5-app-gui-service.yaml'

PKI_GUI_Service = f'''apiVersion: v1
kind: Service
metadata:
  name: app-gui-service
  namespace: {Tanent_Name}  # Namespace belirtilmi�
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

PKI_GUI_Secret_File = '5-app-gui-secret.yaml'

PKI_GUI_Secret = f'''apiVersion: v1
kind: Secret
metadata:
  name: app-gui-secrets
  namespace: {Tanent_Name}
type: Opaque
data:
  Postgresql_User: cG9zdGdyZXNl   # Base64 encoded username 'postgres'
  Postgresql_Password: cG9zdGdyZXNl   # Base64 encoded password 'postgres'
  RabbitUser: bXl1c2Vy   # Base64 encoded RabbitMQ username 'myuser'
  RabbitPassword: bXlwYXNzd29yZA==   # Base64 encoded RabbitMQ password 'mypassword'
  LdapAdminPassword: YWRtaW4=   # Base64 encoded LDAP admin password 'admin'
'''
with open(PKI_GUI_Secret_File, 'w') as dosya:
    dosya.write(PKI_GUI_Secret)

PKI_GUI_PV_File = '5-gui-app-pv.yaml'

PKI_GUI_PV = f'''apiVersion: v1
kind: PersistentVolume
metadata:
  name: gui-app-pv
  namespace: {Tanent_Name}  # Namespace belirtilmi�
spec:
  capacity:
    storage: 1Gi
  accessModes:
    - ReadWriteOnce
  hostPath:
    path: /pki-api/PKI-GUI/app/  # Bu yolu uygun �ekilde g�ncelleyin

'''
with open(PKI_GUI_PV_File, 'w') as dosya:
    dosya.write(PKI_GUI_PV)

Ldap_Deployment_File = '6-ldap-server-deployment.yaml'

Ldap_Deployment = f'''apiVersion: apps/v1
kind: Deployment
metadata:
  name: ldap-server-deployment
  namespace: {Tanent_Name}
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
        image: procenneldap:1.0
        env:
        - name: LDAP_DOMAIN
          value: "procenne.com"
        - name: LDAP_ADMIN_PASSWORD
          valueFrom:
            secretKeyRef:
              name: ldap-server-secrets
              key: LDAP_ADMIN_PASSWORD
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


Ldap_Secret_File = '6-ldap-server-secret.yaml'

Ldap_Secret = f'''apiVersion: v1
kind: Secret
metadata:
  name: ldap-server-secrets
  namespace: {Tanent_Name}
type: Opaque
data:
  LDAP_ADMIN_PASSWORD: YWRtaW4=   # Base64 encoded LDAP admin password 'admin'
'''
with open(Ldap_Secret_File, 'w') as dosya:
    dosya.write(Ldap_Secret)

Ldap_Service_File = '6-ldap-server-service.yaml'

Ldap_Service = f'''apiVersion: v1
kind: Service
metadata:
  name: ldap-server-service
  namespace: {Tanent_Name}  # Namespace belirtilmi�
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


PKI_FTP_Deployment_File = '7-pki-ftp-deployment.yaml'

PKI_FTP_Deployment = f'''apiVersion: apps/v1
kind: Deployment
metadata:
  name: pki-ftp-deployment
  namespace: {Tanent_Name}  # Namespace belirtilmi�
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
          path: /MultiTanent/FTP-Server/data/  # Bu yolu uygun �ekilde g�ncelleyin
'''

with open(PKI_FTP_Deployment_File, 'w') as dosya:
    dosya.write(PKI_FTP_Deployment)

PKI_FTP_Service_File = '7-pki-ftp-service.yaml'

PKI_FTP_Service = f'''apiVersion: v1
kind: Service
metadata:
  name: pki-ftp-service
  namespace: {Tanent_Name}  # Namespace belirtilmi�
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

PKI_Mail_Deployment_File = '8-pki-mail-deployment.yaml'

PKI_Mail_Deployment = f'''apiVersion: apps/v1
kind: Deployment
metadata:
  name: pki-mail-deployment
  namespace: {Tanent_Name}  # Namespace belirtilmi�
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

PKI_Mail_Service_File = '8-pki-mail-service.yaml'

PKI_Mail_Service = f'''apiVersion: v1
kind: Service
metadata:
  name: pki-mail-service
  namespace: {Tanent_Name}  # Namespace belirtilmi�
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

PKI_Alarm_Deployment_File = '9-pki-alarm-deployment.yaml'

PKI_Alarm_Deployment = f'''apiVersion: apps/v1
kind: Deployment
metadata:
  name: pki-alarm-deployment
  namespace: {Tanent_Name}
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
          valueFrom:
            secretKeyRef:
              name: pki-alarm-secrets
              key: Postgresql_User
        - name: Postgresql_Password
          valueFrom:
            secretKeyRef:
              name: pki-alarm-secrets
              key: Postgresql_Password
        - name: Postgresql_IP
          value: "postgres"
        - name: Postgresql_Port
          value: "5432"
        ports:
        - containerPort: 8000
        volumeMounts:
        - name: pki-alarm-volume
          mountPath: /app
        command: ["python3", "manage.py", "runserver"]
      volumes:
      - name: pki-alarm-volume
        hostPath:
          path: /MultiTanent/PKI-Alarm/app  # Update this path accordingly
'''
with open(PKI_Alarm_Deployment_File, 'w') as dosya:
    dosya.write(PKI_Alarm_Deployment)

PKI_Alarm_Secret_File = '9-pki-alarm-secret.yaml'

PKI_Alarm_Secret = f'''apiVersion: v1
kind: Secret
metadata:
  name: pki-alarm-secrets
  namespace: {Tanent_Name}
type: Opaque
data:
  Postgresql_User: cG9zdGdyZXM=   # Base64 encoded username 'postgres'
  Postgresql_Password: cG9zdGdyZXM=   # Base64 encoded password 'postgres'

'''
with open(PKI_Alarm_Secret_File, 'w') as dosya:
    dosya.write(PKI_Alarm_Secret)
PKI_Alarm_Service_File = '9-pki-alarm-service.yaml'

PKI_Alarm_Service = f'''apiVersion: v1
kind: Service
metadata:
  name: pki-alarm-service
  namespace: {Tanent_Name}
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

PKI_Backup_Deployment_File = '10-pki-backup-deployment.yaml'

PKI_Backup_Deployment = f'''apiVersion: apps/v1
kind: Deployment
metadata:
  name: pki-backup-deployment
  namespace: {Tanent_Name}
spec:
  replicas: 1
  selector:
    matchLabels:
      app: pki-backup
  template:
    metadata:
      labels:
        app: pki-backup
    spec:
      containers:
      - name: pki-backup-container
        image: pki-backup-service:1.0

        env:
        - name: Postgresql_DB
          value: "pki_gui_db"
        - name: Postgresql_IP
          value: "postgres"
        - name: API_Slot
          value: "IoaqNDIk1Z9Lx8XL3t13PuoovWvum83U"
        - name: TokenName
          value: "PKI_Client"
        - name: KeyName
          value: "Log_File_Encrypt"
        - name: ftp_host
          value: "pki-ftp"
        - name: Rabbit_Host
          valueFrom:
            secretKeyRef:
              name: pki-backup-secrets
              key: Rabbit_Host
        - name: Postgresql_User
          valueFrom:
            secretKeyRef:
              name: pki-backup-secrets
              key: Postgresql_User
        - name: Postgresql_Password
          valueFrom:
            secretKeyRef:
              name: pki-backup-secrets
              key: Postgresql_Password
        - name: RabbitPassword
          valueFrom:
            secretKeyRef:
              name: pki-backup-secrets
              key: RabbitPassword
        - name: RabbitUser
          valueFrom:
            secretKeyRef:
              name: pki-backup-secrets
              key: RabbitUser
        - name: ftp_user
          valueFrom:
            secretKeyRef:
              name: pki-backup-secrets
              key: ftp_user
        - name: ftp_password
          valueFrom:
            secretKeyRef:
              name: pki-backup-secrets
              key: ftp_password
        ports:
        - containerPort: 8000
        command: ["sleep", "36000"]
        volumeMounts:
        - name: app-volume
          mountPath: /app/
        - name: logs-volume
          mountPath: /opt/BackupLog/
      volumes:
      - name: app-volume
        hostPath:
          path: /MultiTanent/PKI-Alarm/app  # Update this path accordingly
      - name: logs-volume
        hostPath:
          path: /MultiTanent/Backup_Logs/  # Update this path accordingly

'''
with open(PKI_Backup_Deployment_File, 'w') as dosya:
    dosya.write(PKI_Backup_Deployment)


PKI_Backup_Secret_File = '10-pki-backup-secret.yaml'

PKI_Backup_Secret = f'''apiVersion: v1
kind: Secret
metadata:
  name: pki-backup-secrets
  namespace: {Tanent_Name}
type: Opaque
data:
  Postgresql_User: cG9zdGdyZXM=   # Base64 encoded username 'postgres'
  Postgresql_Password: cG9zdGdyZXM=   # Base64 encoded password 'postgres'
  Rabbit_Host: cmFiYml0bXE=
  RabbitUser: bXl1c2Vy
  RabbitPassword: bXlwYXNzd29yZA==
  ftp_user: RlRQQWRtaW4=
  ftp_password: MXEydzNlNHI1dCo=
'''
with open(PKI_Backup_Secret_File, 'w') as dosya:
    dosya.write(PKI_Backup_Secret)

PKI_Backup_Service_File = '10-pki-backup-service.yaml'

PKI_Backup_Service = f'''apiVersion: v1
kind: Service
metadata:
  name: pki-backup-service
  namespace: {Tanent_Name}
spec:
  selector:
    app: pki-backup
  ports:
    - protocol: TCP
      port: 9100
      targetPort: 8000

'''
with open(PKI_Backup_Service_File, 'w') as dosya:
    dosya.write(PKI_Backup_Service)


Start_Bash = f'''kubectl apply -f {Namespace_File}
kubectl apply -f {HSM_Deployment_File}
kubectl apply -f {HSM_Service_File}
kubectl apply -f {PKI_API_Deployment_File}
kubectl apply -f {PKI_API_Service_File}
kubectl apply -f {Rabbitmq_Deployment_File}
kubectl apply -f {Rabbitmq_Service_File}
kubectl apply -f {Postgresql_Deployment_File}
kubectl apply -f {Postgresql_PV_File}
kubectl apply -f {PKI_GUI_Deployment_File}
kubectl apply -f {PKI_GUI_Service_File}
kubectl apply -f {PKI_GUI_PV_File}
kubectl apply -f {Ldap_Deployment_File}
kubectl apply -f {Ldap_Service_File}
kubectl apply -f {PKI_FTP_Deployment_File}
kubectl apply -f {PKI_FTP_Service_File}
kubectl apply -f {PKI_Mail_Deployment_File}
kubectl apply -f {PKI_Mail_Service_File}
kubectl apply -f {PKI_Alarm_Deployment_File}
kubectl apply -f {PKI_Alarm_Service_File}
kubectl apply -f {PKI_Backup_Deployment_File}
kubectl apply -f {PKI_Backup_Secret_File}
kubectl apply -f {PKI_Backup_Service_File}
'''

Start_Bash_File = "StartPKI.sh"
with open(Start_Bash_File, 'w') as dosya:
    dosya.write(Start_Bash)

Delete_Bash = f'''kubectl delete -f {Namespace_File}
kubectl delete -f {HSM_Deployment_File}
kubectl delete -f {HSM_Service_File}
kubectl delete -f {PKI_API_Deployment_File}
kubectl delete -f {PKI_API_Service_File}
kubectl delete -f {Rabbitmq_Deployment_File}
kubectl delete -f {Rabbitmq_Service_File}
kubectl delete -f {Postgresql_Deployment_File}
kubectl delete -f {Postgresql_PV_File}
kubectl delete -f {PKI_GUI_Deployment_File}
kubectl delete -f {PKI_GUI_Service_File}
kubectl delete -f {PKI_GUI_PV_File}
kubectl delete -f {Ldap_Deployment_File}
kubectl delete -f {Ldap_Service_File}
kubectl delete -f {PKI_FTP_Deployment_File}
kubectl delete -f {PKI_FTP_Service_File}
kubectl delete -f {PKI_Mail_Deployment_File}
kubectl delete -f {PKI_Mail_Service_File}
kubectl delete -f {PKI_Alarm_Deployment_File}
kubectl delete -f {PKI_Alarm_Service_File}
kubectl delete -f {PKI_Backup_Deployment_File}
kubectl delete -f {PKI_Backup_Secret_File}
kubectl delete -f {PKI_Backup_Service_File}
'''

Delete_Bash_File = "StopPKI.sh"
with open(Delete_Bash_File, 'w') as dosya:
    dosya.write(Delete_Bash)