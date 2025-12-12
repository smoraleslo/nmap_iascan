# 🛡️ Nmap + Ollama Dashboard (AI Security Auditor)

Este proyecto es una herramienta de ciberseguridad que orquesta escaneos de red con **Nmap**, procesa los resultados y utiliza inteligencia artificial local (**Ollama**) para analizar vulnerabilidades y generar reportes ejecutivos.

## 📋 Requisitos Previos

Antes de comenzar, asegúrate de tener instaladas las siguientes herramientas en tu sistema:

### 1. Python 3.9+
Lenguaje base del proyecto.
- **Descargar:** [python.org](https://www.python.org/downloads/)

### 2. Nmap
El motor de escaneo de red. Debe estar accesible desde la terminal.
- **Linux (Debian/Ubuntu):** `sudo apt install nmap`
- **MacOS:** `brew install nmap`
- **Windows:** [Descargar instalador](https://nmap.org/download.html)

### 3. Git
Necesario para descargar ciertas dependencias.
- **Descargar:** [git-scm.com](https://git-scm.com/)

### 4. Ollama (IA Local)
El motor de inteligencia artificial que analizará los datos.
1. Descarga e instala desde [ollama.com](https://ollama.com).
2. Abre tu terminal y descarga el modelo Llama 3.2:
   ```bash
   ollama pull llama3.2
   ```
3. Asegúrate de que Ollama esté ejecutándose (`ollama serve`).

---

## 🚀 Instalación

Sigue estos pasos para configurar el entorno de desarrollo:

### 1. Clonar o descargar el proyecto
Asegúrate de tener los archivos en la siguiente estructura:
```text
nmap_dashboard/
├── .env                 # Variables de entorno
├── main.py              # Código principal
├── requirements.txt     # Dependencias (crear en paso 3)
├── static/
│   └── styles.css
└── templates/
    └── index.html
```

### 2. Crear un Entorno Virtual
Es recomendable aislar las librerías del proyecto.

**En Windows:**
```bash
python -m venv venv
venv\Scripts\activate
```

**En Linux / Mac:**
```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Instalar Dependencias
Crea un archivo llamado `requirements.txt` con el siguiente contenido:

```text
fastapi
uvicorn[standard]
jinja2
python-multipart
httpx
xmltodict
python-dotenv
```

Ejecuta la instalación:
```bash
pip install -r requirements.txt
```

Adicionalmente, instala la librería de formato TOON:
```bash
pip install git+[https://github.com/toon-format/toon-python.git](https://github.com/toon-format/toon-python.git)
```


---

## ▶️ Ejecución

1. Asegúrate de que **Ollama** esté corriendo en segundo plano.
2. Inicia el servidor FastAPI:

```bash
uvicorn main:app --reload
```

3. Abre tu navegador y ve a: **http://localhost:8000**

---

## 🛠️ Solución de Problemas

| Error | Solución |
|-------|----------|
| `nmap: command not found` | Nmap no está instalado o no está en el PATH del sistema. Reinicia la terminal tras instalarlo. |
| `Connection refused` (Ollama) | Verifica que Ollama esté corriendo (`ollama serve`) y escuchando en el puerto 11434. |
| `git is not recognized` | Instala Git y agrégalo al PATH de tu sistema. |
