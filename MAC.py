from scapy.all import ARP, Ether, srp

#Funcion de buscar en el .txt
def search_str(mac_24bits):
    NIC_unknown = True
    with open('ieee.txt', 'r', errors='ignore') as file:
        # read all content of a file
        for line in file:
            # Verifica si la palabra está en la línea
            if mac_24bits in line:
                print("Fabricante de la NIC:",line)
                NIC_unknown = False
                break
    #Si la MAC no esta en el archivo, se considera que la MAC esta randomizada o aleatorizada
    if NIC_unknown:
        print("Fabricante de la NIC: Desconodicido y/o la MAC esta aleatorizada")


# Define la dirección IP de la red que deseas escanear en formato CIDR
#target_ip = "172.16.12.0/23"
#target_ip = "172.16.8.0/20"
target_ip = "192.168.0.1/24"
# Crea una solicitud ARP para buscar las direcciones MAC en la red
arp = ARP(pdst=target_ip)

# Crea un paquete Ethernet que envuelve la solicitud ARP ----- UNA Trama de broadcast
ether = Ether(dst="ff:ff:ff:ff:ff:ff")

# Combina el paquete Ethernet y la solicitud ARP
packet = ether/arp

# Envía el paquete y recibe las respuestas
result = srp(packet, timeout=3, verbose=0)[0]

# Lista para almacenar las direcciones MAC encontradas
mac_addresses = []

# Procesa las respuestas recibidas
for sent, received in result:
    mac_addresses.append({"IP": received.psrc, "MAC": received.hwsrc})

# Imprime las direcciones MAC,IP y fabricante encontrados
for entry in mac_addresses:
    print("==========================================================================================")
    print("")
    print(f"Direccion IPv4: {entry['IP']}   Direccion MAC: {entry['MAC']}")
    
    #Toma la direcciona MAC del dispositivo, quita los dobles puntos ':', conmvierte todo en mayusculas
    #para hacer una busqueda en el archivo, convierte todo en mayusculas y toma solo 6 elementos del string
    mac_24bits = entry['MAC']
    mac_24bits = mac_24bits.replace(":", "")
    mac_24bits = mac_24bits.upper()
    mac_24bits = mac_24bits[:6]
    search_str(mac_24bits)
    print("")

print("==========================================================================================")
