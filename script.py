import sys
import cryptography
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import time

cipherText = open("xifrat.bin", 'rb').read()

def desxifrar_text(text_xifrat, clau):
    cipher = Cipher(algorithms.AES(clau), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    text_desxifrat = decryptor.update(text_xifrat) + decryptor.finalize()
    return text_desxifrat

def descipherFromHash():
    print("----Desxifrant text amb diccionari de hashos precomputats.")
    file = open("resultat_precomputats.txt", "w")
    hashesFile = open("pbkdf2.txt", "rb")
    start_time = time.time()
    for line in hashesFile:
        line = line.strip()
        try:
            text_desxifrat = desxifrar_text(cipherText[16:], line)
            if text_desxifrat.decode("utf-8"):
                print(f"------El hash de la contraseña és: {line}")
                print(f"------Desxifrat amb diccionari completat")
                file.write(text_desxifrat.decode("utf-8"))
                end_time = time.time()  # Record the end time
                elapsed_time = end_time - start_time
                print(f"-------Temps amb hash SI precomputats: {elapsed_time} segons")
                file.close()
                exit()
        except Exception as e:
            pass

def pbkdf2():
    print("----Desxifrant text sense diccionari de hashos precomputats.")
    file = open("output.txt", "rb")
    with open("pbkdf2.txt", "wb") as binary_file:
        dexifrat = open("resultat_no_precomputats.txt", 'w')
        start_time = time.time()
        for line in file:
            line = line.strip()
            kdf = PBKDF2HMAC(
                algorithm=cryptography.hazmat.primitives.hashes.SHA1(),
                length=16,
                salt=cipherText[8:16],
                iterations=1,
                backend=default_backend()
            )
            key = kdf.derive(line)
            if len(key) != 16:
                print(f"La clau generada per la contrasenya {line} no té la longitud correcta.")
                continue

            binary_file.write(key + b"\n")

            try:
                text_desxifrat = desxifrar_text(cipherText[16:], key)
                
                if text_desxifrat.decode("utf-8"):
                    print(f"------La contrasenya és: {line}")
                    print(f"------Desxifrat completat")
                    dexifrat.write(text_desxifrat.decode("utf-8"))
                    end_time = time.time()  # Record the end time
                    elapsed_time = end_time - start_time
                    print(f"-------Temps amb hash NO precomputat: {elapsed_time} segons")
            except Exception as e:
                pass

        file.close()
        binary_file.close()
        dexifrat.close()

def passwordsGeneration():
    print("--Generant diccionari.")
    if len(sys.argv) != 2:
        print("Usage: python3 script.py <file>")
        sys.exit(1)
    try:
        file = open(sys.argv[1], "r")
        outputFile = open("output.txt", "w")
    except:
        print("Error: file not found")
        sys.exit(1)
    for line in file:
        line = line.strip()
        outputFile.write(line + "\n")
        for i in range(0, 10):
            outputFile.write(line + str(i) + "\n")
            for j in range(0, 10):
                outputFile.write(line + str(i) + str(j) + "\n")
    file.close()
    outputFile.close()
    print("--Diccionari generat.")


if __name__ == "__main__":
    passwordsGeneration()
    pbkdf2()
    descipherFromHash()
