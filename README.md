# 🛡️ Laboratorio: Canales Encubiertos ICMP y Criptoanálisis César

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Scapy](https://img.shields.io/badge/Scapy-2.7.0-red?style=for-the-badge)](https://scapy.net/)
[![Platform Windows](https://img.shields.io/badge/Platform-Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white)](https://microsoft.com)
[![Wireshark](https://img.shields.io/badge/Capture-Wireshark%20%2F%20PCAPNG-1679A7?style=for-the-badge&logo=wireshark&logoColor=white)](https://www.wireshark.org/)

Proyecto integral de ciberseguridad enfocado en la **exfiltración de datos mediante canales encubiertos ICMP (Covert Channels)** con técnicas de evasión de sistemas **DPI (Deep Packet Inspection)**, combinado con **cifrado clásico (César)** y **criptoanálisis automatizado** asistido por análisis de frecuencias en idioma español.

---

## 📋 Tabla de Contenidos
- [Arquitectura del Proyecto](#-arquitectura-del-proyecto)
- [Componentes del Sistema](#-componentes-del-sistema)
  - [1. Cifrado César (`cesar.py`)](#1-cifrado-césar-cesarpy)
  - [2. Inyección Stealth ICMP (`pingv4.py`)](#2-inyección-stealth-icmp-pingv4py)
  - [3. Extracción y Criptoanálisis (`readv2.py`)](#3-extracción-y-criptoanálisis-readv2py)
- [Estructura del Payload ICMP (Evasión DPI)](#-estructura-del-payload-icmp-evasión-dpi)
- [Requisitos Previos e Instalación](#-requisitos-previos-e-instalación)
- [Guía de Uso Paso a Paso](#-guía-de-uso-paso-a-paso)
- [Resultados de Ejecución](#-resultados-de-ejecución)
- [Cómo Subir este Proyecto a GitHub](#-cómo-subir-este-proyecto-a-github)

---

## 📐 Arquitectura del Proyecto

El flujo de trabajo simula un escenario de exfiltración encubierta y posterior análisis forense de red:

```
+------------------------------------+
| Texto en claro                     |
| "criptografia y seguridad en redes"|
+-----------------+------------------+
                  |
                  v [cesar.py (Shift = 9)]
+-----------------+------------------+
| Texto Cifrado                      |
| "larycxpajorj h bnpdarmjm nw anmnb"|
+-----------------+------------------+
                  |
                  v [pingv4.py (Inyección Stealth ICMP)]
+-----------------+------------------+
| Canales Encubiertos ICMP (Red)     |
| [1 byte por Echo Request / 56B]    |
+-----------------+------------------+
                  |
                  v [cesar.pcapng (Wireshark / Sniffer)]
+-----------------+------------------+
| Extracción & Criptoanálisis        |
| [readv2.py]                        |
| -> Extracción de offsets           |
| -> Fuerza Bruta (1..25)            |
| -> Heurística de frecuencia ES     |
| -> Identificación de llave         |
+------------------------------------+
```

---

## 🧩 Componentes del Sistema

### 1. Cifrado César (`cesar.py`)
Módulo encargado de aplicar una transposición alfabética mediante el algoritmo César.
- Mantiene mayúsculas, minúsculas, espacios y caracteres especiales intactos.
- Soporta desplazamientos positivos y rotación modular (`mod 26`).

### 2. Inyección Stealth ICMP (`pingv4.py`)
Transmisor encubierto que encapsula cada carácter del mensaje cifrado dentro de paquetes `ICMP Echo Request`.
- **Evasión DPI**: Mimetiza exactamente el formato y tamaño (56 bytes) de un ping legítimo en Windows.
- **Campos de cabecera coherentes**:
  - `IP ID`: Secuencia correlativa incremental.
  - `ICMP ID`: Asociado al identificador del proceso en ejecución (`PID & 0xFFFF`).
  - `Sequence Number`: Numeración secuencial a partir de 1.
- Introduce un retardo de 0.5s entre transmisiones para mitigar anomalías temporales en firewalls/IDS.

### 3. Extracción y Criptoanálisis (`readv2.py`)
Herramienta de análisis forense y criptoanálisis automático sobre archivos `.pcap` o `.pcapng`.
- **Extracción de tráfico**: Filtra paquetes `ICMP Type 8` (Echo Request) y extrae el byte encubierto alojado en el offset `0x08`.
- **Ordenamiento**: Reordena los caracteres según su número de secuencia ICMP para mitigar desorden de paquetes.
- **Criptoanálisis Heurístico**:
  - Genera las 25 variantes de descifrado.
  - Evalúa cada variante usando la distribución de frecuencias del alfabeto español (`e`, `a`, `o`, `s`, `r`, `n`, `i`, `d`, etc.).
  - Aplica bonificaciones ponderadas por detección de términos comunes del idioma y palabras técnicas del dominio de redes/seguridad.
  - Resalta automáticamente la solución correcta en color verde en la consola.

---

## 🔍 Estructura del Payload ICMP (Evasión DPI)

Para burlar firmas de inspección profunda de paquetes (DPI) y parecer tráfico ICMP nativo de Windows, el payload se construye con exactamente **56 bytes**:

| Rango de Bytes | Offset | Tamaño | Descripción |
| :--- | :---: | :---: | :--- |
| `0x00 - 0x07` | 0 a 7 | 8 bytes | **Timestamp simulado** (`struct.pack("<II", int(time.time()), 0)`) |
| `0x08` | 8 | 1 byte | **Carácter encubierto** del mensaje cifrado |
| `0x09 - 0x0F` | 9 a 15 | 7 bytes | **Padding nulo** (`\x00` * 7) |
| `0x10 - 0x37` | 16 a 55 | 40 bytes | **Secuencia estándar Windows** (`0x10` hasta `0x37`) |

---

## ⚙️ Requisitos Previos e Instalación

### Requisitos del Sistema
- **Sistema Operativo**: Windows 10 u 11.
- **Python**: 3.10 o superior.
- **Npcap**: Necesario para el envío y captura de paquetes RAW con Scapy en Windows. Descargar con soporte WinPcap desde [npcap.com](https://npcap.com/).
- **Permisos de Administrador**: Requeridos por el sistema operativo para crear sockets RAW.

### Instalación de Dependencias

1. Clonar el repositorio o posicionarse en la carpeta del proyecto:
   ```powershell
   cd lab1
   ```

2. Crear y activar un entorno virtual (opcional pero recomendado):
   ```powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```

3. Instalar dependencias requeridas:
   ```powershell
   pip install -r requirements.txt
   ```

---

## 🚀 Guía de Uso Paso a Paso

> [!IMPORTANT]
> Para el envío de paquetes con `pingv4.py`, abra su terminal de PowerShell o CMD como **Administrador**.

### Paso 1: Cifrar el mensaje
Cifre el mensaje que desea transmitir especificando el texto y el desplazamiento deseado:
```powershell
python cesar.py "criptografia y seguridad en redes" 9
```
*Salida:*
```text
larycxpajorj h bnpdarmjm nw anmnb
```

### Paso 2: Transmitir encubiertamente vía ICMP
Ejecute la inyección stealth indicando el texto cifrado y opcionalmente la dirección IP destino (por defecto `8.8.8.8`):
```powershell
python pingv4.py "larycxpajorj h bnpdarmjm nw anmnb" 8.8.8.8
```
*Salida:*
```text
Sent 1 packets.
Sent 1 packets.
...
```

### Paso 3: Analizar la captura y recuperar el mensaje
Procese la captura generada (`cesar.pcapng`) para extraer la información y romper el cifrado de forma automática:
```powershell
python readv2.py cesar.pcapng
```

---

## 📊 Resultados de Ejecución

Al ejecutar `readv2.py cesar.pcapng`, el motor de puntuación lingüística descarta los desplazamientos incoherentes y resalta en **verde** la clave correcta identificada:

```text
Mensaje cifrado extraído: larycxpajorj h bnpdarmjm nw anmnb

--- Criptoanálisis de Fuerza Bruta (25 combinaciones) ---
[-] Shift 01: kzqxbwozinqi g amoczqlil mv zmlma
[-] Shift 02: jypwavnyhmph f zlnbypkhk lu ylklz
[-] Shift 03: ixovzumxglog e ykmaxojgj kt xkjky
[-] Shift 04: hwnuytlwfknf d xjlzwnifi js wjijx
[-] Shift 05: gvmtxskvejme c wikyvmheh ir vihiw
[-] Shift 06: fulswrjudild b vhjxulgdg hq uhghv
[-] Shift 07: etkrvqitchkc a ugiwtkfcf gp tgfgu
[-] Shift 08: dsjquphsbgjb z tfhvsjebe fo sfeft
[+] Shift 09: criptografia y seguridad en redes   <-- [IDENTIFICADO AUTOMÁTICAMENTE]
[-] Shift 10: bqhosnfqzehz x rdftqhczc dm qdcdr
[-] Shift 11: apgnrmepydgy w qcespgbyb cl pcbcq
[-] Shift 12: zofmqldoxcfx v pbdrofaxa bk obabp
[-] Shift 13: ynelpkcnwbew u oacqnezwz aj nazao
[-] Shift 14: xmdkojbmvadv t nzbpmdyvy zi mzyzn
[-] Shift 15: wlcjnialuzcu s myaolcxux yh lyxym
[-] Shift 16: vkbimhzktybt r lxznkbwtw xg kxwxl
[-] Shift 17: ujahlgyjsxas q kwymjavsv wf jwvwk
[-] Shift 18: tizgkfxirwzr p jvxlizuru ve ivuvj
[-] Shift 19: shyfjewhqvyq o iuwkhytqt ud hutui
[-] Shift 20: rgxeidvgpuxp n htvjgxsps tc gtsth
[-] Shift 21: qfwdhcufotwo m gsuifwror sb fsrsg
[-] Shift 22: pevcgbtensvn l frthevqnq ra erqrf
[-] Shift 23: odubfasdmrum k eqsgdupmp qz dqpqe
[-] Shift 24: nctaezrclqtl j dprfctolo py cpopd
[-] Shift 25: mbszdyqbkpsk i coqebsnkn ox bonoc
```

---

## 🌐 Cómo Subir este Proyecto a GitHub

Siga estos pasos para publicar este laboratorio en su cuenta de GitHub:

1. Ingrese a [https://github.com/new](https://github.com/new) y cree un nuevo repositorio (por ejemplo, con el nombre `lab1-covert-icmp-crypto`).
   - Deje desmarcada la opción de inicializar con README (ya lo tenemos creado aquí).

2. En su terminal de PowerShell en `c:\Users\marti\Desktop\lab1`, ejecute:

```powershell
# Inicializar repositorio Git
git init

# Agregar todos los archivos (el .gitignore omitirá .venv automáticamente)
git add .

# Crear el primer commit
git commit -m "feat: implementacion inicial del laboratorio de canales encubiertos ICMP y criptoanalisis"

# Renombrar rama a main
git branch -M main

# Vincular con su repositorio remoto (reemplace con su usuario y nombre de repo)
git remote add origin https://github.com/SU_USUARIO/lab1-covert-icmp-crypto.git

# Subir los cambios a GitHub
git push -u origin main
```

---

## ⚖️ Licencia y Aviso Académico
Este proyecto ha sido desarrollado exclusivamente con fines **académicos y educativos** para la comprensión de técnicas de seguridad en redes, esteganografía de paquetes y análisis de protocolos de comunicación.
