# This script dexcipher a ciphered file calculating the hash from every line of a dictionary and trying it. Then uses the already precalculated hashes and desciphers again.
import sys
import cryptography
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import padding

cipherText = open("xifrat.bin", 'rb').read()

def desxifrar_text(text_xifrat, clau):
    cipher = Cipher(algorithms.AES(clau), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    text_desxifrat = decryptor.update(text_xifrat) + decryptor.finalize()
    return text_desxifrat

def descipherFromHash():
    print("Descifrant text...")
    hashesFile = open("pbkdf2.txt", "rb")
    for line in hashesFile:
        line = line.strip()
        try:
            text_desxifrat = desxifrar_text(cipherText[16:], line)
            if text_desxifrat.decode("utf-8"):
                print(f"El hash de la contraseña és: {line}")
                print(f"Desxifrat completat")
                exit()
        except Exception as e:
            pass

def pbkdf2():
    file = open("output.txt", "rb")
    with open("pbkdf2.txt", "wb") as binary_file:
        dexifrat = open("desxifrat.txt", 'w')
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
                    print(f"La contrasenya és: {line}")
                    print(f"Desxifrat completat")
                    dexifrat.write(text_desxifrat.decode("utf-8"))
            except Exception as e:
                pass

        file.close()
        binary_file.close()
        dexifrat.close()

def passwordsGeneration():
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
                print(line + str(i) + str(j))
    file.close()
    outputFile.close()


if __name__ == "__main__":
    "We start by generating the dictionary of all words that will be a password"
    #passwordsGeneration()
    "Once we have generated the passwords on plain text. We generate the passwords on pbkdf2"
    pbkdf2()
    descipherFromHash()
    
