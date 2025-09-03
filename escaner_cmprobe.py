#!/usr/bin/env python3

import nmap
import argparse
import threading
from queue import Queue
import time
import os
import sys

# Bloqueo para evitar que los hilos de impresión se mezclen
print_lock = threading.Lock()

def banner():
    print("""
###########################################################
#                                                         #
#                    CMProbe                              #
#      Primer escáner de puertos por Cristian Muñoz       #
#                                                         #
#                      (2025)                             #
#                                                         #
###########################################################
    """)

def check_host(host):
    """
    Verifica si el host está activo usando un escaneo de ping de nmap.
    """
    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=host, arguments='-sn')
        return host in nm.all_hosts()
    except Exception:
        return False

def escaner_de_puertos(host, puerto, tipo_escaneo, verbose, output):
    """
    Escanea un solo puerto y maneja la salida.
    """
    try:
        nm = nmap.PortScanner()
        if tipo_escaneo == 'tcp':
            # Se agregó la opción --host-timeout para evitar que el programa se cuelgue
            nm.scan(host, arguments=f'-sS -sV -p {puerto} --host-timeout 30s')
            protocolo = 'tcp'
        elif tipo_escaneo == 'udp':
            # Se agregó la opción --host-timeout para evitar que el programa se cuelgue
            nm.scan(host, arguments=f'-sU -sV -p {puerto} --host-timeout 30s')
            protocolo = 'udp'
            
        if host in nm.all_hosts():
            if protocolo in nm[host] and puerto in nm[host][protocolo]:
                estado = nm[host][protocolo][puerto]['state']
                
                output_message = f"Puerto {puerto}/{protocolo} - Estado: {estado.capitalize()}"
                
                if verbose:
                    with print_lock:
                        print(output_message)
                
                if output:
                    output.write(output_message + '\n')

                if estado == 'open':
                    with print_lock:
                        info_servicio = nm[host][protocolo][puerto]
                        open_message = f"\nPuerto {puerto}/{protocolo} está abierto\n  Servicio: {info_servicio.get('name', 'Desconocido')}\n  Versión: {info_servicio.get('version', 'Desconocida')}\n  Producto: {info_servicio.get('product', 'Desconocido')}"
                        print(open_message)
                        if output:
                            output.write(open_message + '\n')
            
    except nmap.PortScannerError as e:
        # Se modificó para capturar y mostrar errores de Nmap, en lugar de ignorarlos
        print(f"\n[!] Error de escaneo en el puerto {puerto}: {e}")
    except Exception as e:
        # Para cualquier otro error inesperado
        print(f"\n[!] Error inesperado en el puerto {puerto}: {e}")


def worker(cola, host, tipo_escaneo, verbose, output):
    """
    Toma puertos de la cola y los escanea.
    """
    while not cola.empty():
        puerto = cola.get()
        escaner_de_puertos(host, puerto, tipo_escaneo, verbose, output)
        cola.task_done()

def main():
    """
    Función principal para manejar argumentos y hilos.
    """
    banner()
    
    parser = argparse.ArgumentParser(description="Escáner de puertos SYN rápido con multithreading.")
    parser.add_argument("-t", "--target", dest="target", required=True, help="Dirección IP o nombre de host a escanear.")
    parser.add_argument("-p", "--ports", dest="ports", required=True, help="Lista de puertos o rangos (Ejemplo: 80,443,1-1000).")
    parser.add_argument("-u", "--udp", dest="udp_scan", action="store_true", help="Realiza un escaneo de puertos UDP.")
    parser.add_argument("-v", "--verbose", dest="verbose", action="store_true", help="Muestra el progreso del escaneo en tiempo real.")
    
    args = parser.parse_args()
    
    host = args.target
    tipo_escaneo = 'tcp' if not args.udp_scan else 'udp'
    verbose_mode = args.verbose
    
    output = None
    home_dir = os.path.expanduser("~")
    base_dir = os.path.join(home_dir, "Escritorio", "CMProbe")
    resultados_dir = os.path.join(base_dir, "Resultados de Escaneo")
    
    if not os.path.exists(resultados_dir):
        os.makedirs(resultados_dir)
        
        info_file_path = os.path.join(resultados_dir, "informacion_escaner.txt")
        with open(info_file_path, "w") as info_file:
            info_file.write("****************************************\n")
            info_file.write("          Resultados de CMProbe\n")
            info_file.write("          by Cristian Muñoz 2025\n")
            info_file.write("****************************************\n\n")
            info_file.write("Este archivo contiene los resultados de los escaneos realizados por el escáner de puertos CMProbe.\n")

    timestamp = time.strftime("%Y-%m-%d_%H-%M-%S")
    output_filename = f"{args.target}_{timestamp}.txt"
    output_path = os.path.join(resultados_dir, output_filename)
    try:
        output = open(output_path, 'w')
    except IOError:
        print(f"\n[!] Error: No se puede crear el archivo de salida en el Escritorio. Saliendo...")
        sys.exit(1)
    
    if not check_host(host):
        print(f"\n[!] El objetivo {host} parece estar inactivo. Saliendo...")
        if output:
            output.close()
        sys.exit(1)

    puertos = set()
    for item in args.ports.split(','):
        if '-' in item:
            inicio, fin = map(int, item.split('-'))
            puertos.update(range(inicio, fin + 1))
        else:
            puertos.add(int(item))

    cola = Queue()
    for puerto in puertos:
        cola.put(puerto)

    print(f"\n[+] Objetivo {host} está activo. Escaneando el rango {args.ports}\n")
    if output:
        output.write(f"\n[+] Objetivo {host} está activo. Escaneando el rango {args.ports}\n\n")

    inicio = time.time()
    
    hilos = []
    for _ in range(50):
        hilo = threading.Thread(target=worker, args=(cola, host, tipo_escaneo, verbose_mode, output))
        hilo.daemon = True
        hilo.start()
        hilos.append(hilo)
    
    cola.join()
    
    fin = time.time()
    
    final_message = f"\nEscaneo completo en {fin - inicio:.2f} segundos."
    print(final_message)
    if output:
        output.write(final_message + '\n')
        output.close()
    
    # Se eliminaron los comandos 'os.system' y 'os._exit'
    # para mejorar la compatibilidad y la limpieza del programa.

if __name__ == "__main__":
    main()
