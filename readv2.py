import os
import sys
import logging

# Habilitar soporte para secuencias de escape ANSI en Windows CMD/PowerShell
os.system("color")

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

try:
    from scapy.all import rdpcap, ICMP, Raw
except ImportError:
    print("Error: Scapy no está instalado. Ejecute 'pip install scapy'", file=sys.stderr)
    sys.exit(1)

# Frecuencia relativa de letras en el idioma español (%)
SPANISH_LETTER_FREQ = {
    'e': 13.68, 'a': 12.53, 'o': 8.68, 's': 7.98, 'r': 6.87, 'n': 6.71,
    'i': 6.25, 'd': 5.86, 'l': 4.97, 'c': 4.68, 't': 4.63, 'u': 3.93,
    'm': 3.15, 'p': 2.51, 'b': 1.42, 'g': 1.01, 'v': 0.90, 'y': 0.90,
    'q': 0.88, 'h': 0.70, 'f': 0.69, 'z': 0.52, 'j': 0.44, 'x': 0.22,
    'w': 0.01, 'k': 0.01
}

COMMON_SPANISH_WORDS = {
    "de", "la", "que", "el", "en", "y", "a", "los", "se", "del", "las",
    "por", "un", "para", "con", "no", "una", "su", "al", "lo", "como",
    "mas", "pero", "sus", "le", "ya", "o", "este", "si", "porque", "esta",
    "entre", "cuando", "muy", "sin", "sobre", "ser", "tiene", "tambien",
    "me", "hasta", "hay", "donde", "quien", "desde", "todo", "nos",
    "redes", "seguridad", "criptografia", "sistema", "datos", "mensaje"
}

def extract_message_from_pcap(filepath: str) -> str:
    """
    Lee un archivo pcap/pcapng, extrae paquetes ICMP Echo Request
    y recupera el byte en el offset 0x08 ordenado por número de secuencia.
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"No se encontró el archivo: {filepath}")

    packets = rdpcap(filepath)
    extracted_chars = {}

    for pkt in packets:
        if pkt.haslayer(ICMP) and pkt[ICMP].type == 8:
            payload = bytes(pkt[ICMP].payload)
            if len(payload) >= 9:
                seq = pkt[ICMP].seq
                if seq not in extracted_chars:
                    char = chr(payload[8])
                    extracted_chars[seq] = char

    if not extracted_chars:
        return ""

    sorted_seqs = sorted(extracted_chars.keys())
    return "".join(extracted_chars[s] for s in sorted_seqs)

def caesar_decrypt(ciphertext: str, shift: int) -> str:
    """Descifra el texto con un desplazamiento dado."""
    result = []
    shift = shift % 26
    for char in ciphertext:
        if 'a' <= char <= 'z':
            base = ord('a')
            result.append(chr((ord(char) - base - shift) % 26 + base))
        elif 'A' <= char <= 'Z':
            base = ord('A')
            result.append(chr((ord(char) - base - shift) % 26 + base))
        else:
            result.append(char)
    return "".join(result)

def calculate_spanish_score(text: str) -> float:
    """Evalúa la probabilidad de que el texto esté en español."""
    score = 0.0
    clean_text = text.lower()

    # Ponderación por frecuencia de letras
    for char in clean_text:
        score += SPANISH_LETTER_FREQ.get(char, 0.0)

    # Bonificación por coincidencia de palabras comunes
    words = clean_text.split()
    for word in words:
        clean_word = "".join(c for c in word if c.isalpha())
        if clean_word in COMMON_SPANISH_WORDS:
            score += 45.0

    return score

def main():
    if len(sys.argv) != 2:
        print("Uso: python readv2.py <archivo.pcap / archivo.pcapng>", file=sys.stderr)
        sys.exit(1)

    pcap_path = sys.argv[1]

    try:
        ciphertext = extract_message_from_pcap(pcap_path)
    except Exception as e:
        print(f"Error al procesar el archivo PCAP: {e}", file=sys.stderr)
        sys.exit(1)

    if not ciphertext:
        print("No se encontraron paquetes ICMP Echo Request válidos con payload.", file=sys.stderr)
        sys.exit(1)

    print(f"Mensaje cifrado extraído: {ciphertext}\n")
    print("--- Criptoanálisis de Fuerza Bruta (25 combinaciones) ---")

    decryptions = []
    best_shift = 1
    best_score = -1.0

    for shift in range(1, 26):
        decrypted = caesar_decrypt(ciphertext, shift)
        score = calculate_spanish_score(decrypted)
        decryptions.append((shift, decrypted, score))

        if score > best_score:
            best_score = score
            best_shift = shift

    # Mostrar resultados resaltando únicamente la combinación correcta en verde
    GREEN = "\033[92m"
    RESET = "\033[0m"

    for shift, text, _ in decryptions:
        if shift == best_shift:
            print(f"{GREEN}[+] Shift {shift:02d}: {text}{RESET}")
        else:
            print(f"[-] Shift {shift:02d}: {text}")

if __name__ == "__main__":
    main()