import smtplib

def Send_Mail(sender,receiver,message):
    with smtplib.SMTP("sandbox.smtp.mailtrap.io", 2525) as server:
        server.login("5d26c5b4f47d8a", "26866cfe03dd40")
        server.sendmail(sender, receiver, message)


# sender = "Private Person <from@example.com>"
# receiver = "A Test User <to@example.com>"

# message = f"""\
# Subject: Hi Mailtrap
# To: {receiver}
# From: {sender}

# The certificate has expired."""

# Send_Mail(sender,receiver,message)