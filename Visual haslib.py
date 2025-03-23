import tkinter as tk
from tkinter import ttk, messagebox
import hashlib

#D4N13LCI no se responsabiliza por el uso ilegal de este programa.

class DNIApp:
    def __init__(self, root):
        self.root = root
        root.title("Generador de DNI Educativo (No Real)")
        root.geometry("500x380")
        root.minsize(450, 350)
        root.configure(bg="#e0e0e0")  

        self.style = ttk.Style()
        self.style.theme_use("clam")  
        self.configure_styles()
        self.create_widgets()

    def configure_styles(self):
        self.style.configure("TFrame", background="#e0e0e0")
        self.style.configure("TLabel", background="#e0e0e0", font=("Segoe UI", 11))
        self.style.configure("TButton", font=("Segoe UI", 11, "bold"), padding=5)
        self.style.configure("TEntry", font=("Segoe UI", 11), fieldbackground="white")
        self.style.configure("TMenubutton", background="#e0e0e0", font=("Segoe UI", 11))  # Para OptionMenu
        self.style.configure("Error.TLabel", background="#e0e0e0", foreground="#d63031", font=("Segoe UI", 11, "bold"))  # Rojo más vivo
        self.style.configure("Result.TLabel", background="#e0e0e0", font=("Segoe UI", 12, "bold"))
        self.style.map("TButton",
            foreground=[("pressed", "white"), ("active", "white")],  # Texto blanco al presionar/activar
            background=[("pressed", "!disabled", "#27ae60"), ("active", "#2ecc71")] # Verde al presionar
        )


    def create_widgets(self):
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(main_frame, text="Nombres:", style="TLabel").grid(row=0, column=0, sticky=tk.W, pady=5, padx=(0, 5))
        self.nombres_entry = ttk.Entry(main_frame, width=35, style="TEntry")
        self.nombres_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), pady=5, padx=(5, 0))

        ttk.Label(main_frame, text="Apellidos:", style="TLabel").grid(row=1, column=0, sticky=tk.W, pady=5, padx=(0, 5))
        self.apellidos_entry = ttk.Entry(main_frame, width=35, style="TEntry")
        self.apellidos_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), pady=5, padx=(5, 0))

        ttk.Label(main_frame, text="País:", style="TLabel").grid(row=2, column=0, sticky=tk.W, pady=5, padx=(0,5))
        self.pais_var = tk.StringVar()
        self.pais_combo = ttk.Combobox(main_frame, textvariable=self.pais_var, width=32, style="TMenubutton", state="readonly")  # readonly
        self.pais_combo['values'] = list(self.regiones_por_pais.keys())  # Lista de países
        self.pais_combo.grid(row=2, column=1, sticky=(tk.W, tk.E), pady=5, padx=(5, 0))
        self.pais_combo.bind("<<ComboboxSelected>>", self.actualizar_regiones) # Evento al seleccionar país

        ttk.Label(main_frame, text="Región:", style="TLabel").grid(row=3, column=0, sticky=tk.W, pady=5, padx=(0,5))
        self.region_var = tk.StringVar()
        self.region_combo = ttk.Combobox(main_frame, textvariable=self.region_var, width=32, style="TMenubutton", state="disabled")  # Inicia deshabilitado
        self.region_combo.grid(row=3, column=1, sticky=(tk.W, tk.E), pady=5, padx=(5, 0))

        button_frame = ttk.Frame(main_frame, style="TFrame")  # Frame para los botones
        button_frame.grid(row=4, column=0, columnspan=2, pady=15)

        self.generar_button = ttk.Button(button_frame, text="Generar DNI", command=self.generar_dni, style="TButton")
        self.generar_button.pack(side=tk.LEFT, padx=10)

        self.limpiar_button = ttk.Button(button_frame, text="Limpiar", command=self.limpiar_campos, style="TButton")
        self.limpiar_button.pack(side=tk.LEFT, padx=10)

        self.resultado_label = ttk.Label(main_frame, text="", style="Result.TLabel")
        self.resultado_label.grid(row=5, column=0, columnspan=2, pady=(0, 10))

        aviso_text = "AVISO IMPORTANTE:\nEste generador crea DNIs EDUCATIVOS y NO REALES.  Los DNIs generados NO son válidos para identificación oficial y su uso indebido es ilegal. Esta herramienta es solo para fines de aprendizaje y demostración de conceptos de programación."
        aviso_label = ttk.Label(main_frame, text=aviso_text, style="Error.TLabel", wraplength=450, justify=tk.CENTER)  # Centrado
        aviso_label.grid(row=6, column=0, columnspan=2, pady=(0, 10))

        for i in range(7):
            main_frame.rowconfigure(i, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=3)  
        button_frame.columnconfigure(0, weight=1)
        button_frame.columnconfigure(1, weight=1)
    
    regiones_por_pais = {
    "Afganistán": ["Otra"],
    "Albania": ["Otra"],
    "Alemania": ["Berlín", "Múnich", "Hamburgo", "Fráncfort", "Colonia", "Otra"],
    "Andorra": ["Otra"],
    "Angola": ["Otra"],
    "Antigua y Barbuda": ["Otra"],
    "Arabia Saudita": ["Otra"],
    "Argelia": ["Otra"],
    "Argentina": ["Buenos Aires", "Córdoba", "Rosario", "Mendoza", "Tucumán", "La Plata", "Otra"],
    "Armenia": ["Otra"],
    "Australia": ["Sídney", "Melbourne", "Brisbane", "Perth", "Adelaida", "Otra"],
    "Austria": ["Otra"],
    "Azerbaiyán": ["Otra"],
    "Bahamas": ["Otra"],
    "Bangladés": ["Otra"],
    "Barbados": ["Otra"],
    "Baréin": ["Otra"],
    "Bélgica": ["Otra"],
    "Belice": ["Otra"],
    "Benín": ["Otra"],
    "Bielorrusia": ["Otra"],
    "Birmania (Myanmar)": ["Otra"],
    "Bolivia": ["La Paz", "Santa Cruz de la Sierra", "Cochabamba", "El Alto", "Otra"],
    "Bosnia y Herzegovina": ["Otra"],
    "Botsuana": ["Otra"],
    "Brasil": ["São Paulo", "Río de Janeiro", "Brasilia", "Salvador", "Fortaleza", "Otra"],
    "Brunéi": ["Otra"],
    "Bulgaria": ["Otra"],
    "Burkina Faso": ["Otra"],
    "Burundi": ["Otra"],
    "Bután": ["Otra"],
    "Cabo Verde": ["Otra"],
    "Camboya": ["Otra"],
    "Camerún": ["Otra"],
    "Canadá": ["Toronto", "Montreal", "Vancouver", "Calgary", "Ottawa", "Otra"],
    "Catar": ["Otra"],
    "Chad": ["Otra"],
    "Chile": ["Santiago", "Valparaíso", "Concepción", "Otra"],
    "China": ["Pekín", "Shanghái", "Cantón", "Shenzhen", "Otra"],
    "Chipre": ["Otra"],
    "Ciudad del Vaticano": ["Otra"],
    "Colombia": ["Bogotá", "Medellín", "Cali", "Barranquilla", "Cartagena", "Otra"],
    "Comoras": ["Otra"],
    "Corea del Norte": ["Otra"],
    "Corea del Sur": ["Seúl", "Busan", "Incheon", "Daegu", "Otra"],
    "Costa de Marfil": ["Otra"],
    "Costa Rica": ["Otra"],
    "Croacia": ["Otra"],
    "Cuba": ["Otra"],
    "Dinamarca": ["Otra"],
    "Dominica": ["Otra"],
    "Ecuador": ["Quito", "Guayaquil", "Cuenca", "Otra"],
    "Egipto": ["Otra"],
    "El Salvador": ["Otra"],
    "Emiratos Árabes Unidos": ["Otra"],
    "Eritrea": ["Otra"],
    "Eslovaquia": ["Otra"],
    "Eslovenia": ["Otra"],
    "España": ["Madrid", "Barcelona", "Valencia", "Sevilla", "Zaragoza", "Málaga", "Murcia", "Otra"],
    "Estados Unidos": ["Nueva York", "Los Ángeles", "Chicago", "Houston", "Filadelfia", "Otra"],
    "Estonia": ["Otra"],
    "Esuatini": ["Otra"],
    "Etiopía": ["Otra"],
    "Filipinas": ["Otra"],
    "Finlandia": ["Otra"],
    "Fiyi": ["Otra"],
    "Francia": ["París", "Marsella", "Lyon", "Toulouse", "Niza", "Otra"],
    "Gabón": ["Otra"],
    "Gambia": ["Otra"],
    "Georgia": ["Otra"],
    "Ghana": ["Otra"],
    "Granada": ["Otra"],
    "Grecia": ["Otra"],
    "Guatemala": ["Otra"],
    "Guinea": ["Otra"],
    "Guinea-Bisáu": ["Otra"],
    "Guinea Ecuatorial": ["Otra"],
    "Guyana": ["Otra"],
    "Haití": ["Otra"],
    "Honduras": ["Otra"],
    "Hungría": ["Otra"],
    "India": ["Bombay", "Delhi", "Bangalore", "Hyderabad", "Chennai", "Otra"],
    "Indonesia": ["Otra"],
    "Irak": ["Otra"],
    "Irán": ["Otra"],
    "Irlanda": ["Otra"],
    "Islandia": ["Otra"],
    "Islas Marshall": ["Otra"],
    "Islas Salomón": ["Otra"],
    "Israel": ["Otra"],
    "Italia": ["Roma", "Milán", "Nápoles", "Turín", "Otra"],
    "Jamaica": ["Otra"],
    "Japón": ["Tokio", "Yokohama", "Osaka", "Nagoya", "Otra"],
    "Jordania": ["Otra"],
    "Kazajistán": ["Otra"],
    "Kenia": ["Otra"],
    "Kirguistán": ["Otra"],
    "Kiribati": ["Otra"],
    "Kuwait": ["Otra"],
    "Laos": ["Otra"],
    "Lesoto": ["Otra"],
    "Letonia": ["Otra"],
    "Líbano": ["Otra"],
    "Liberia": ["Otra"],
    "Libia": ["Otra"],
    "Liechtenstein": ["Otra"],
    "Lituania": ["Otra"],
    "Luxemburgo": ["Otra"],
    "Macedonia del Norte": ["Otra"],
    "Madagascar": ["Otra"],
    "Malasia": ["Otra"],
    "Malaui": ["Otra"],
    "Maldivas": ["Otra"],
    "Malí": ["Otra"],
    "Malta": ["Otra"],
    "Marruecos": ["Otra"],
    "Mauricio": ["Otra"],
    "Mauritania": ["Otra"],
    "México": ["Ciudad de México", "Guadalajara", "Monterrey", "Puebla", "Tijuana", "Otra"],
    "Micronesia": ["Otra"],
    "Moldavia": ["Otra"],
    "Mónaco": ["Otra"],
    "Mongolia": ["Otra"],
    "Montenegro": ["Otra"],
    "Mozambique": ["Otra"],
    "Namibia": ["Otra"],
    "Nauru": ["Otra"],
    "Nepal": ["Otra"],
    "Nicaragua": ["Otra"],
    "Níger": ["Otra"],
    "Nigeria": ["Otra"],
    "Noruega": ["Otra"],
    "Nueva Zelanda": ["Otra"],
    "Omán": ["Otra"],
    "Países Bajos": ["Otra"],
    "Pakistán": ["Otra"],
    "Palaos": ["Otra"],
    "Panamá": ["Otra"],
    "Papúa Nueva Guinea": ["Otra"],
    "Paraguay": ["Otra"],
    "Perú": ["Lima", "Arequipa", "Cusco", "Trujillo", "Chiclayo", "Iquitos", "Otra"],
    "Polonia": ["Otra"],
    "Portugal": ["Lisboa", "Oporto", "Otra"],
    "Reino Unido": ["Londres", "Birmingham", "Glasgow", "Liverpool", "Otra"],
    "República Centroafricana": ["Otra"],
    "República Checa": ["Otra"],
    "República del Congo": ["Otra"],
    "República Democrática del Congo": ["Otra"],
    "República Dominicana": ["Otra"],
    "Ruanda": ["Otra"],
    "Rumania": ["Otra"],
    "Rusia": ["Moscú", "San Petersburgo", "Otra"],
    "Samoa": ["Otra"],
    "San Cristóbal y Nieves": ["Otra"],
    "San Marino": ["Otra"],
    "San Vicente y las Granadinas": ["Otra"],
    "Santa Lucía": ["Otra"],
    "Santo Tomé y Príncipe": ["Otra"],
    "Senegal": ["Otra"],
    "Serbia": ["Otra"],
    "Seychelles": ["Otra"],
    "Sierra Leona": ["Otra"],
    "Singapur": ["Otra"],
    "Siria": ["Otra"],
    "Somalia": ["Otra"],
    "Sri Lanka": ["Otra"],
    "Sudáfrica": ["Otra"],
    "Sudán": ["Otra"],
    "Sudán del Sur": ["Otra"],
    "Suecia": ["Otra"],
    "Suiza": ["Otra"],
    "Surinam": ["Otra"],
    "Tailandia": ["Otra"],
    "Tanzania": ["Otra"],
    "Tayikistán": ["Otra"],
    "Timor Oriental": ["Otra"],
    "Togo": ["Otra"],
    "Tonga": ["Otra"],
    "Trinidad y Tobago": ["Otra"],
    "Túnez": ["Otra"],
    "Turkmenistán": ["Otra"],
    "Turquía": ["Otra"],
    "Tuvalu": ["Otra"],
    "Ucrania": ["Otra"],
    "Uganda": ["Otra"],
    "Uruguay": ["Otra"],
    "Uzbekistán": ["Otra"],
    "Vanuatu": ["Otra"],
    "Venezuela": ["Caracas", "Maracaibo", "Valencia", "Otra"],
    "Vietnam": ["Otra"],
    "Yemen": ["Otra"],
    "Yibuti": ["Otra"],
    "Zambia": ["Otra"],
    "Zimbabue": ["Otra"],
    "Otro": ["Otra"]
}


    def actualizar_regiones(self, event=None):
        """
        Actualiza la lista de regiones en función del país seleccionado.
        """
        pais = self.pais_var.get()
        if pais:
            regiones = self.regiones_por_pais.get(pais, []) 
            self.region_combo['values'] = regiones
            self.region_combo.config(state="readonly") 
            self.region_var.set("") 

            if not regiones:
                self.region_combo.config(state="disabled")
        else:
            self.region_combo.config(state="disabled") 
            self.region_var.set("")
            self.region_combo['values'] = []

    def generar_dni(self):
        nombres = self.nombres_entry.get().strip()
        apellidos = self.apellidos_entry.get().strip()
        region = self.region_var.get().strip()
        pais = self.pais_var.get().strip()

        if not all([nombres, apellidos, region, pais]):
            messagebox.showerror("Error", "Todos los campos son obligatorios.")
            return

        dni_educativo = self.generar_dni_educativo(nombres, apellidos, region)  

        if dni_educativo.startswith("Error"):
            messagebox.showerror("Error", dni_educativo)
        else:
            self.resultado_label.config(text=f"DNI Educativo: {dni_educativo}")

    def generar_dni_educativo(self, nombres, apellidos, region):
        if not all([nombres, apellidos, region]):
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

    def limpiar_campos(self):
        self.nombres_entry.delete(0, tk.END)
        self.apellidos_entry.delete(0, tk.END)
        self.region_var.set("")
        self.pais_var.set("")
        self.region_combo.config(state="disabled")
        self.resultado_label.config(text="")



if __name__ == "__main__":
    root = tk.Tk()
    app = DNIApp(root)
    root.mainloop()