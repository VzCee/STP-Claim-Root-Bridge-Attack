# 🌐 STP Claim Root Bridge Attack Tool

## 🧨 Spanning Tree Protocol – Root Bridge Claim

Este proyecto es una herramienta educativa desarrollada en Python utilizando Scapy y Tkinter para simular un ataque STP Claim Root Bridge dentro de un entorno de laboratorio controlado.

El script envía BPDUs maliciosos con prioridad superior para forzar que el dispositivo atacante sea elegido como Root Bridge, provocando la reconfiguración de la topología de red.

---

## 🎯 Función del Script

La función principal del script es:

- Construir BPDUs (Configuration BPDUs) falsificados.
- Anunciar una prioridad inferior (mayor prioridad).
- Reclamar ser el Root Bridge.
- Forzar a los switches a recalcular la topología STP.
- Redirigir el tráfico de red a través del atacante.

Esto puede permitir escenarios de:

- Man-in-the-Middle (MITM)
- Intercepción de tráfico entre switches
- Manipulación del flujo de red
- Interrupciones temporales de conectividad
<img width="350" height="350" alt="Screenshot 2026-02-13 170334" src="https://github.com/user-attachments/assets/2b24f2d5-878a-432d-a6a8-ea5b3fce38a2" />


---

## 🔑 Características Clave

- Construcción manual de BPDUs con Scapy.
- Configuración personalizada de Bridge Priority.
- Configuración de Root Path Cost.
- Envío continuo de BPDUs cada 2 segundos.
- Simulación realista del Hello Time STP.
- Interfaz gráfica para monitoreo.
- Contador en tiempo real de BPDUs enviados.
- Validación de ejecución con privilegios root.

---
## Video de Demostracion
**https://youtu.be/ENO_J61DHog?si=nILQLLmrKkhw3ELV**

## 🖥 Topología Representada en PNETLab
<img width="1209" height="830" alt="image" src="https://github.com/user-attachments/assets/89850eeb-ba17-48d7-82e5-cc3e3786cdce" />


### 🔌 Router

| Conexión | Interfaz Router | Dispositivo Destino | Interfaz Destino |
|----------|-----------------|---------------------|-------------------|
| LAN      | e0/0            | Switch Principal    | e0/0              |
| WAN      | e0/1            | Net                 | -                 |

IP LAN: 23.72.0.1  
Gateway: 23.72.0.1  

---

### 🖧 Switch Principal

| Interfaz | Dispositivo Conectado | Interfaz Destino |
|----------|----------------------|------------------|
| e0/0     | Router               | e0/0             |
| e0/1     | Atacante             | eth0             |
| e0/2     | VPC 1                | eth0             |
| e1/0     | VPC 2                | eth0             |
| e1/1     | Víctima              | eth0             |
| e0/3     | Switch 2             | e0/0             |

---

### 🖧 Switch 2

| Interfaz | Dispositivo Conectado | Interfaz Destino |
|----------|----------------------|------------------|
| e0/0     | Switch Principal     | e0/3             |
| e0/2     | VPC 3                | eth0             |

---

### 🧨 Atacante (Linux)

| Interfaz | Conectado a        | Interfaz Destino |
|----------|-------------------|------------------|
| eth0     | Switch Principal  | e0/1             |

Sistema: Kali / Ubuntu  
Modo: Acceso Layer 2  

---

## 📋 Requisitos Técnicos

- Linux (Kali, Ubuntu, Debian)
- Python 3.8 o superior
- Permisos de superusuario (root)
- Acceso al mismo dominio Layer 2 que los switches
- Entorno de laboratorio controlado

---

## 📦 Dependencias

Instalar dependencias del sistema:

```bash
sudo apt update
sudo apt install python3-scapy python3-tk
```

requirements.txt:

```
scapy>=2.5.0
```

Instalar con:

```bash
pip install -r requirements.txt
```

---

## 🔐 Permisos

El script requiere privilegios root debido al envío de tramas Ethernet (Layer 2).

Ejecutar con:

```bash
sudo python3 stp_attack.py
```

---

## 🌐 Requisitos de Red

- Switches con STP habilitado.
- Sin BPDU Guard activado (para pruebas).
- Sin Root Guard configurado.
- Todos los dispositivos dentro del mismo dominio Layer 2.
- Red de laboratorio aislada.

---

# 🛡 Medidas de Mitigación contra STP Root Bridge Attack

---

## 1️⃣ BPDU Guard (Recomendado)

Bloquea puertos donde no deberían recibirse BPDUs.

Ejemplo Cisco:

```
interface range e0/1 - e0/24
 spanning-tree bpduguard enable
```

---

## 2️⃣ Root Guard

Impide que un switch no autorizado se convierta en Root Bridge.

```
interface e0/1
 spanning-tree guard root
```

---

## 3️⃣ Configurar Prioridad Manual del Root

Definir explícitamente el Root Bridge legítimo:

```
spanning-tree vlan 1 priority 4096
```

---

## 4️⃣ PortFast en Puertos de Acceso

Reduce superficie de ataque en puertos hacia usuarios finales.

---

## 5️⃣ Monitoreo de Eventos STP

Indicadores de ataque:

- Cambio inesperado de Root Bridge.
- Recalculación frecuente de topología.
- Logs de STP topology change.
- Pérdidas intermitentes de conectividad.

---

# 🎯 Enfoque Defensivo

El objetivo del laboratorio no es solo ejecutar el ataque, sino:

- Comprender cómo funciona STP.
- Analizar el proceso de elección del Root Bridge.
- Identificar configuraciones vulnerables.
- Implementar mecanismos de protección.
- Validar controles defensivos.

---

# ⚠️ Advertencia

Esta herramienta debe utilizarse exclusivamente en entornos de laboratorio autorizados.

El uso indebido en redes reales sin consentimiento constituye una violación legal.
