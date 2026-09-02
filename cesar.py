import sys

def caesar_cipher(text: str, shift: int) -> str:
    """
    Cifra una cadena de texto utilizando el algoritmo César.
    Conserva mayúsculas, minúsculas, espacios y caracteres especiales.
    """
    result = []
    shift = shift % 26

    for char in text:
        if 'a' <= char <= 'z':
            base = ord('a')
            result.append(chr((ord(char) - base + shift) % 26 + base))
        elif 'A' <= char <= 'Z':
            base = ord('A')
            result.append(chr((ord(char) - base + shift) % 26 + base))
        else:
            result.append(char)

    return "".join(result)

def main():
    if len(sys.argv) != 3:
        print("Uso: python cesar.py <texto> <desplazamiento>", file=sys.stderr)
        sys.exit(1)

    text = sys.argv[1]
    try:
        shift = int(sys.argv[2])
    except ValueError:
        print("Error: El desplazamiento debe ser un número entero.", file=sys.stderr)
        sys.exit(1)

    encrypted_text = caesar_cipher(text, shift)
    print(encrypted_text)

if __name__ == "__main__":
    main()