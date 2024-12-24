import ipaddress
import socket
def is_valid_ip(ip_str):
    try:
        ipaddress.IPv4Address(ip_str)
        return True
    except ipaddress.AddressValueError:
        try:
            ipaddress.IPv6Address(ip_str)
            return True
        except ipaddress.AddressValueError:
            return False

def are_all_ips(ip_list):
    for ip_str in ip_list:
        if not is_valid_ip(ip_str):
            return False
    return True

def is_valid_port(port_str):
    try:
        port = int(port_str)
        return 0 <= port <= 65535
    except ValueError:
        return False

def are_all_ports(port_list):
    for port_str in port_list:
        if not is_valid_port(port_str):
            return False
    return True

def is_connection_successful(ip, port):
    if not is_valid_ip(ip) or not is_valid_port(port):
        return False
    
    try:
        with socket.create_connection((ip, int(port)), timeout=1):
            return True
    except socket.error:
        return False

def ConfigFileWrite(IP_Address,Port_Address):
    IP_Address_Array = IP_Address.split(",")
    Port_Address_Array = Port_Address.split(",")
    try:
        if are_all_ips(IP_Address_Array):
            # Zipli iterasyon
            for ip, port in zip(IP_Address_Array, Port_Address_Array):
                if is_connection_successful(ip, port):
                    pass
                else:
                    # Güncelleme işlemleri
                    index = IP_Address_Array.index(ip)
                    IP_Address_Array.pop(index)
                    Port_Address_Array.pop(index)
            counter = len(IP_Address_Array)
            IP_List = ""
            for i in range(counter):
                IP_List = IP_List + str(IP_Address_Array[i]) +","
            Config = '***** HSM	Id		Ip			Port		Type		Status		Description\n'
            for i in range(counter):
                Config += f'HSM		{i}		{IP_Address_Array[i]}		{Port_Address_Array[i]}		Independent	Active		\n'
            Config += '***** PIN	status\n'
            Config += 'USER		true\n'
            Config += 'SO		true\n'
            Config += '***** HIGH AVAILABILITY mode status\n'
            Config += 'HIGH_AV		false\n'
            Config += '***** DEFAULTS\n'
            Config += f'DEF_IP		{IP_Address_Array[0]}\n'
            Config += f'DEF_PORT	{Port_Address_Array[i]}\n'
            Config += 'DEF_ID		0\n'
            dosya_tam_yolu = "/opt/procrypt/km3000/config/" + "config"
            with open(dosya_tam_yolu, "w") as dosya:
                dosya.write(Config)
            result = str(IP_List[:-1]) + " IP addresses activated"
        else:
            result = "You entered missing IP address and port information"
    except:
        result = "Specified HSM Pool is incorrect"
    return result





# def ConfigFileWrite(IP_Address,Port_Address):
#     try:
#         Write_Array = []
#         line1 = "***** HSM	Id		Ip			Port		Type		Status		Description"
#         Write_Array.append(line1)
#         IP_Address_Array = IP_Address.split(",")
#         IP_Array_length = len(IP_Address_Array)
#         Port_Address_Array = Port_Address.split(",")
#         Port_Array_length = len(Port_Address_Array)
#         Count = min(IP_Array_length, Port_Array_length)
#         for i in range(Count):
#             line_connect = f"HSM		{i}		{IP_Address_Array[i]}		{Port_Address_Array[i]}		Independent	Active	"
#             Write_Array.append(line_connect)
#         line3 = "***** PIN	status"
#         line4 = "USER		true"
#         line5 = "SO		true"
#         line6 = "***** HIGH AVAILABILITY mode status"
#         line7 = "HIGH_AV		false"
#         line8 = "***** DEFAULTS"
#         line9 = f"DEF_IP		{IP_Address_Array[0]}"
#         line10 = f"DEF_PORT	{Port_Address_Array[0]}"
#         line11 = f"DEF_ID		0"
#         Write_Array.append(line3)
#         Write_Array.append(line4)
#         Write_Array.append(line5)
#         Write_Array.append(line6)
#         Write_Array.append(line7)
#         Write_Array.append(line8)
#         Write_Array.append(line9)
#         Write_Array.append(line10)
#         Write_Array.append(line11)
#         with open('/opt/procrypt/km3000/config/config', 'w') as dosya:
#             for satir in Write_Array:
#                 dosya.write(satir + '\n')
#         result = "Successful"
#     except:
#         result = "Select HSM Pool Error"
#     return result
# IP_Address = "172.16.0.4"
# Port_Address = "5000"

# ConfigFileWrite(IP_Address,Port_Address)