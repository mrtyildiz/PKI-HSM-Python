import acme

# CA'dan bir ACME hesabı oluşturun
account = acme.Account("example.com")

# Etki alanını doğrulayın
challenge = acme.challenge.HTTP01(account, "example.com")
challenge.answer()

# Sertifika başvurusu yapın
csr = acme.csr.CSR()
csr.subject.commonName = "example.com"

order = account.newOrder(csr)
order.finalize()

# Sertifikayı alın
cert = order.certificate()

# Sertifikayı kaydedin
with open("cert.pem", "wb") as f:
    f.write(cert.pem)
