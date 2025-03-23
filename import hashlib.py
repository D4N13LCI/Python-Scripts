import hashlib
import random

#D4N13LCI> se puede usar para obtener registros en SQL..
#D4N13LCI> no se hace responsable por el mal uso del script...

def generar_dni_educativo(nombres, apellidos, region):

    if not all([nombres, apellidos, region]):  # Validación básica
        return "Error: Todos los campos (nombres, apellidos, región) son obligatorios."

    if not isinstance(nombres, str) or not isinstance(apellidos, str) or not isinstance(region, str):
         return "Error: Nombres, apellidos y región deben ser cadenas de texto."

    datos_concatenados = nombres.lower().strip() + apellidos.lower().strip() + region.lower().strip()

    hash_objeto = hashlib.sha256(datos_concatenados.encode('utf-8'))
    hash_hex = hash_objeto.hexdigest()


    digitos = ""
    for i in range(0, 16, 2):  
        digitos += hash_hex[i]


    try:
        numero_dni = int(digitos, 16)  
    except ValueError:
        return "Error: No se pudo generar el DNI (problema interno con el hash)."

    numero_dni_str = str(numero_dni).zfill(8) 
    numero_dni_str = numero_dni_str[-8:]   

    letras = "TRWAGMYFPDXBNJZSQVHLCKE"
    resto = int(numero_dni_str) % 23
    letra = letras[resto]

    return numero_dni_str + letra

def main():

    print("Generador de DNI Educativo (NO REAL)")
    print("-" * 40)

    while True: 
        nombres = input("Ingrese nombres (o deje en blanco para salir): ").strip()
        if not nombres:
            break  
        
        apellidos = input("Ingrese apellidos: ").strip()

        region = input("Ingrese región (ej. Lima, Cusco, etc.): ").strip()

        dni_educativo = generar_dni_educativo(nombres, apellidos, region)
    
        if dni_educativo.startswith("Error"):
            print(dni_educativo)  # Mostrar el mensaje de error
        else:
            print(f"DNI Educativo generado: {dni_educativo}")

        print("-" * 40)

if __name__ == "__main__":
    main()

#FSOCIETY