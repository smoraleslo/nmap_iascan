import asyncio
import json
import httpx  # Reemplazo asíncrono de requests
import xmltodict
from datetime import datetime
from typing import List, Dict, Any, Optional
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

# TOON encoder
# pip install git+https://github.com/toon-format/toon-python.git
from toon_format import encode as toon_encode

app = FastAPI(title="Nmap + Ollama Dashboard (Async)")

# Static & templates
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# Configuración
OLLAMA_URL = "http://localhost:11434/api/chat"
OLLAMA_MODEL = "llama3.2"

# ---------- UTILIDADES ----------
def estimate_tokens(s: str) -> int:
    return len(s.split())

# ---------- CAPA NMAP (ASÍNCRONA) ----------
async def run_nmap_xml_async(
    target: str, 
    profile: str = "quick", 
    no_ping: bool = False, 
    os_detect: bool = False, 
    vuln_scripts: bool = False
) -> tuple[str, str]:
    """
    Ejecuta Nmap de forma asíncrona sin bloquear el servidor.
    """
    base_cmd = ["nmap", "-sV", "-sC", "-v"]

    if profile == "quick":
        base_cmd += ["--top-ports", "100"]
    else:
        base_cmd += ["-p-", "-T4"]

    if no_ping:
        base_cmd.append("-Pn")
    if os_detect:
        base_cmd.append("-O")
    if vuln_scripts:
        base_cmd += ["--script", "vuln"]

    base_cmd += ["-oX", "-", target]

    # Ejecución asíncrona del subproceso
    process = await asyncio.create_subprocess_exec(
        *base_cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )

    stdout, stderr = await process.communicate()
    
    # Decodificar bytes a string
    xml_output = stdout.decode().strip()
    scan_log = stderr.decode().strip()

    if process.returncode != 0:
        raise RuntimeError(f"Error ejecutando Nmap:\n{scan_log}")

    return xml_output, scan_log

def parse_nmap_xml(xml_str: str) -> Dict[str, Any]:
    # (El código de parseo se mantiene igual, es CPU bound pero rápido)
    if not xml_str:
        return {"summary": {}, "hosts": []}
        
    data = xmltodict.parse(xml_str)
    nmaprun = data.get("nmaprun", {})
    hosts_raw = nmaprun.get("host", [])

    if isinstance(hosts_raw, dict):
        hosts_raw = [hosts_raw]

    hosts: List[Dict[str, Any]] = []
    for host in hosts_raw:
        addr = host.get("address", {})
        if isinstance(addr, list):
            addr = addr[0] if addr else {}
        else: 
            addr = addr if addr else {} # Handle single dict or None
            
        ip = addr.get("@addr", "desconocido")

        hostnames_block = host.get("hostnames", {})
        hostname = None
        if hostnames_block:
            hn = hostnames_block.get("hostname")
            if isinstance(hn, dict):
                hostname = hn.get("@name")
            elif isinstance(hn, list) and hn:
                hostname = hn[0].get("@name")

        ports_block = host.get("ports", {})
        ports_raw = ports_block.get("port", [])
        if isinstance(ports_raw, dict):
            ports_raw = [ports_raw]

        ports: List[Dict[str, Any]] = []
        for p in ports_raw:
            state = p.get("state", {}).get("@state")
            if state != "open":
                continue
            service = p.get("service", {}) or {}
            ports.append({
                "port": int(p.get("@portid")),
                "proto": p.get("@protocol"),
                "state": state,
                "service": service.get("@name"),
                "product": service.get("@product"),
                "version": service.get("@version"),
            })

        if ports:
            hosts.append({
                "ip": ip,
                "hostname": hostname,
                "ports": sorted(ports, key=lambda x: x["port"]),
            })

    summary = {
        "total_hosts": len(hosts),
        "hosts_with_open_ports": len(hosts),
    }
    return {"summary": summary, "hosts": hosts}

# ---------- TOON + IA (ASÍNCRONO) ----------
def build_toon_from_scan(scan_data: Dict[str, Any]) -> tuple[Dict[str, Any], str]:
    # (Se mantiene igual)
    rows = []
    for host in scan_data["hosts"]:
        for p in host["ports"]:
            rows.append({
                "ip": host["ip"],
                "hostname": host["hostname"],
                "port": p["port"],
                "proto": p["proto"],
                "service": p["service"],
                "product": p["product"],
                "version": p["version"],
            })
    payload_struct = {"summary": scan_data["summary"], "entries": rows}
    toon_text = toon_encode(payload_struct)
    return payload_struct, toon_text

async def analyze_with_ollama_async(toon_text: str, target: str, profile: str) -> str:
    """
    Llamada asíncrona a Ollama usando HTTPX.
    """
    mega_prompt = f"""
    Actúa como un Auditor Senior de Ciberseguridad (SecOps).
    
    OBJETIVO:
    Realizar una auditoría técnica y de comportamiento de red basada en el escaneo Nmap (formato TOON) del objetivo: {target}.
    
    INPUT DATA (Nmap TOON):
    {toon_text}
    
    INSTRUCCIONES DE SALIDA (Usa formato Markdown estricto con estos encabezados):
    
    1. 🛡️ **Resumen Ejecutivo**: 
       - Diagnóstico de salud del host y puntuación de riesgo (1-10).
       - Superficie de ataque (cantidad de puertos expuestos).
    
    2. 🚨 **Matriz de Riesgos**:
       - Tabla: [Puerto | Servicio | Versión | Severidad | CVE/Riesgo].
       - Destaca versiones obsoletas como CRÍTICAS.
    
    3. 🔍 **Análisis Técnico Profundo**:
       - Explica los vectores de ataque de los puertos críticos detectados.
       - Identifica fugas de información en los banners (SO, versiones exactas).
       
    4. 📡 **Análisis de Patrones de Tráfico y Latencia**:
       - **Conectividad**: Analiza la diferencia entre puertos 'closed' (rechazo activo/RST) vs 'filtered' (silencio/drop). ¿Qué nos dice esto sobre el Firewall?
       - **Latencia/Rendimiento**: Si Nmap detectó servicios pero no versiones, ¿indica esto lentitud o timeouts?
       - **Anomalías**: ¿Hay puertos no estándar abiertos (ej. SSH en 2222) o patrones de puertos secuenciales?
    
    5. 🛠️ **Plan de Remediación**:
       - Comandos técnicos exactos (iptables, configuración de servicios).
       - Estrategias de "Defense in Depth".
    
    IMPORTANTE:
    - Sé técnico y conciso.
    - Si ves muchos 'filtered', asume presencia de Firewall/IPS bloqueando paquetes.
    """.strip()

    payload = {
        "model": OLLAMA_MODEL,
        "messages": [{"role": "user", "content": mega_prompt}],
        "stream": False,
    }

    async with httpx.AsyncClient(timeout=300.0) as client:
        resp = await client.post(OLLAMA_URL, json=payload)
        resp.raise_for_status()
        data = resp.json()
        return data["message"]["content"]

# ---------- RUTAS ----------

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    # Renderiza la página inicial limpia
    return templates.TemplateResponse("index.html", {
        "request": request,
        "result": None,
        "error": None,
        "target": "",
    })

@app.websocket("/ws/scan")
async def websocket_scan(websocket: WebSocket):
    """
    Maneja el escaneo en tiempo real enviando actualizaciones de progreso.
    """
    await websocket.accept()
    
    try:
        # 1. Recibir configuración del frontend
        data = await websocket.receive_json()
        target = data.get("target")
        profile = data.get("profile", "quick")
        no_ping = data.get("no_ping", False)
        os_detect = data.get("os_detect", False)
        vuln_scripts = data.get("vuln_scripts", False)

        if not target:
            await websocket.send_json({"status": "error", "message": "Falta el objetivo (target)."})
            return

        # 2. Paso 1: Nmap
        await websocket.send_json({
            "status": "progress", 
            "step": "nmap", 
            "percent": 10, 
            "message": f"Iniciando escaneo Nmap a {target}..."
        })

        xml_output, scan_log = await run_nmap_xml_async(target, profile, no_ping, os_detect, vuln_scripts)
        
        await websocket.send_json({
            "status": "progress", 
            "step": "parsing", 
            "percent": 50, 
            "message": "Escaneo completado. Procesando datos..."
        })

        # 3. Paso 2: Parsing y TOON
        scan_struct = parse_nmap_xml(xml_output)
        
        if not scan_struct["hosts"]:
            await websocket.send_json({"status": "error", "message": "Nmap finalizó pero no se detectaron puertos abiertos."})
            return

        payload_struct, toon_text = build_toon_from_scan(scan_struct)

        # Token stats
        json_repr = json.dumps(payload_struct, ensure_ascii=False)
        json_tokens = estimate_tokens(json_repr)
        toon_tokens = estimate_tokens(toon_text)
        saved_tokens = max(json_tokens - toon_tokens, 0)
        saved_percent = (saved_tokens / json_tokens * 100) if json_tokens > 0 else 0.0

        token_stats = {
            "json_tokens": json_tokens,
            "toon_tokens": toon_tokens,
            "saved_tokens": saved_tokens,
            "saved_percent": round(saved_percent, 1),
        }

        # 4. Paso 3: Ollama
        await websocket.send_json({
            "status": "progress", 
            "step": "ollama", 
            "percent": 60, 
            "message": "Analizando vulnerabilidades con IA (Ollama)..."
        })

        analysis = await analyze_with_ollama_async(toon_text, target, profile)

        # 5. Finalizar y enviar todo
        meta = {
            "tool": "nmap-ollama-dashboard",
            "target": target,
            "generated_at": datetime.utcnow().isoformat() + "Z",
        }
        
        full_result = {
            "scan": scan_struct,
            "analysis": analysis,
            "scan_log": scan_log,
            "token_stats": token_stats,
            "meta": meta
        }

        # Generar el JSON de exportación
        export_json = json.dumps({"meta": meta, "scan": scan_struct, "analysis": analysis}, ensure_ascii=False, indent=2)

        await websocket.send_json({
            "status": "complete",
            "percent": 100,
            "message": "Análisis finalizado.",
            "data": full_result,
            "export_json": export_json
        })

    except Exception as e:
        import traceback
        traceback.print_exc()
        await websocket.send_json({"status": "error", "message": str(e)})