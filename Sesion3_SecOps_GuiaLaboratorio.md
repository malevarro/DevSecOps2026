# Guía de Laboratorio — Sesión 3
## Análisis de Vulnerabilidades y DevSecOps con herramientas contenerizadas en Azure Container Instances

> **Curso:** SecOps — Seguridad de Aplicaciones y DevSecOps
> **Docente:** Manuel Alejandro Vargas Rojas — manuelvargasrojas@cedoc.edu.co
> **Nivel:** Posgrado · **Uso:** interno
> **Base:** ampliación y modernización de [DevSecOps-Lab/Laboratorio 2](https://github.com/malevarro/DevSecOps-Lab/blob/master/Laborarotio%202.md)
> **Aplicaciones de trabajo:** [malevarro/nodejs-goof](https://github.com/malevarro/nodejs-goof) y [malevarro/AzureGoat](https://github.com/malevarro/AzureGoat)

**Novedad de esta versión — sin máquina virtual / OVA del curso.** El único software instalado en el equipo del estudiante es **Visual Studio Code** (con las extensiones de las herramientas), **Git for Windows** y el **cliente de Tailscale**. **Todas** las herramientas de escaneo (Trivy, Checkov, SonarQube, OWASP ZAP) y la aplicación objetivo corren **contenerizadas en Azure Container Instances (ACI)**, desplegadas **en la red del Laboratorio 2**. La orquestación se hace desde **Azure Cloud Shell** (navegador, sin instalar nada), los reportes se recogen desde un recurso compartido **Azure Files**, y el estudiante accede a las **interfaces web de los ACI (SonarQube, la app) a través de la red privada** usando **Tailscale**, con la **VM-Spoke1** del Lab 2 actuando como *subnet router*.

**Red:** los ACI **salen a Internet por la UDR del Lab 2 (a través de Zentyal)** — no se usa NAT Gateway — reforzando que todo el egreso (incluido el de las herramientas) queda inspeccionado por el firewall del laboratorio.

---

## Tabla de contenido

- [Guía de Laboratorio — Sesión 3](#guía-de-laboratorio--sesión-3)
  - [Análisis de Vulnerabilidades y DevSecOps con herramientas contenerizadas en Azure Container Instances](#análisis-de-vulnerabilidades-y-devsecops-con-herramientas-contenerizadas-en-azure-container-instances)
  - [Tabla de contenido](#tabla-de-contenido)
  - [Objetivo](#objetivo)
  - [Aplicaciones de trabajo](#aplicaciones-de-trabajo)
  - [Entorno del laboratorio (sin VM/OVA)](#entorno-del-laboratorio-sin-vmova)
  - [Métodos de análisis y mapa al OWASP Top 10:2025](#métodos-de-análisis-y-mapa-al-owasp-top-102025)
  - [Requisitos y preparación](#requisitos-y-preparación)
    - [A. Cuentas en línea](#a-cuentas-en-línea)
    - [B. Preparar la red del Lab 2 para ACI](#b-preparar-la-red-del-lab-2-para-aci)
    - [C. Acceso remoto a las redes privadas con Tailscale](#c-acceso-remoto-a-las-redes-privadas-con-tailscale)
      - [C.1 – Crear la cuenta de Tailscale](#c1--crear-la-cuenta-de-tailscale)
      - [C.2 – Instalar el cliente en el equipo del estudiante (Windows)](#c2--instalar-el-cliente-en-el-equipo-del-estudiante-windows)
      - [C.3 – Instalar Tailscale en VM-Spoke1 y habilitarla como *subnet router*](#c3--instalar-tailscale-en-vm-spoke1-y-habilitarla-como-subnet-router)
      - [C.4 – Habilitar el reenvío de IP en Azure para VM-Spoke1](#c4--habilitar-el-reenvío-de-ip-en-azure-para-vm-spoke1)
      - [C.5 – Aprobar las rutas y aceptar en el equipo del estudiante](#c5--aprobar-las-rutas-y-aceptar-en-el-equipo-del-estudiante)
      - [C.6 – Probar el acceso](#c6--probar-el-acceso)
    - [D. Clonar el código fuente al recurso compartido](#d-clonar-el-código-fuente-al-recurso-compartido)
  - [Parte 1 – Análisis en línea de los repositorios (SaaS)](#parte-1--análisis-en-línea-de-los-repositorios-saas)
    - [1.1 – Snyk](#11--snyk)
    - [1.2 – SonarCloud](#12--sonarcloud)
    - [1.3 – Qwiet AI (ShiftLeft)](#13--qwiet-ai-shiftleft)
  - [Parte 2 – Análisis en el IDE (Visual Studio Code)](#parte-2--análisis-en-el-ide-visual-studio-code)
    - [2.1 – Clonar los repos en el equipo (con Git for Windows)](#21--clonar-los-repos-en-el-equipo-con-git-for-windows)
    - [2.2 – Instalar extensiones en VS Code](#22--instalar-extensiones-en-vs-code)
    - [2.3 – Activar y revisar](#23--activar-y-revisar)
  - [Parte 3 – SCA y contenedores con Trivy en ACI](#parte-3--sca-y-contenedores-con-trivy-en-aci)
  - [Parte 4 – SAST de IaC con Checkov en ACI](#parte-4--sast-de-iac-con-checkov-en-aci)
  - [Parte 6 – DAST con OWASP ZAP en ACI](#parte-6--dast-con-owasp-zap-en-aci)
    - [6.1 – Construir la imagen de la app sin Docker local (ACR Tasks)](#61--construir-la-imagen-de-la-app-sin-docker-local-acr-tasks)
    - [6.2 – Desplegar MongoDB y la app en la red privada](#62--desplegar-mongodb-y-la-app-en-la-red-privada)
    - [6.3 – Ejecutar OWASP ZAP (baseline) contra la app privada](#63--ejecutar-owasp-zap-baseline-contra-la-app-privada)
  - [Parte 7 – IAST (concepto y demostración)](#parte-7--iast-concepto-y-demostración)
  - [Parte 8 – AzureGoat: despliegue opcional en Azure](#parte-8--azuregoat-despliegue-opcional-en-azure)
  - [Recoger los reportes y acceder a las UIs](#recoger-los-reportes-y-acceder-a-las-uis)
  - [Remediación y re-escaneo](#remediación-y-re-escaneo)
  - [Limpieza](#limpieza)
  - [Checklist de finalización](#checklist-de-finalización)
  - [Solución de problemas frecuentes](#solución-de-problemas-frecuentes)
  - [Referencias](#referencias)

---

## Objetivo

Realizar análisis de vulnerabilidades sobre **código**, **dependencias**, **infraestructura como código** y **contenedores** con distintos métodos (**SCA, SAST, DAST, IAST**), **sin instalar herramientas ni usar Docker en el equipo del estudiante**: las herramientas se ejecutan como **contenedores en Azure Container Instances** dentro de la red construida en el Laboratorio 2. El estudiante determinará vulnerabilidades reales, las relacionará con el **OWASP Top 10:2025** y remediará al menos una por método.

Al finalizar, el estudiante será capaz de:

- Analizar repositorios con herramientas SaaS integradas a GitHub (SCA/SAST).
- Detectar vulnerabilidades **mientras codifica** con extensiones de VS Code (shift-left), sin instalar motores adicionales.
- Ejecutar **Trivy, Checkov, SonarQube y OWASP ZAP como contenedores en ACI**, en la red privada del Lab 2, con **egreso a través de Zentyal (UDR, sin NAT Gateway)**, y recoger sus reportes desde **Azure Files**.
- Habilitar **acceso remoto seguro** a todas las redes privadas de la arquitectura (incluidas las UIs de los ACI) mediante **Tailscale**, con **VM-Spoke1** como *subnet router*.
- Comprender y demostrar el enfoque **IAST**.
- **Opcionalmente**, desplegar AzureGoat con Terraform y auditar la infraestructura real (DAST + CSPM).
- Priorizar y remediar hallazgos, y verificar la corrección con un re-escaneo.

---

## Aplicaciones de trabajo

| Aplicación | Qué es | Uso en el lab |
|---|---|---|
| **nodejs-goof** (`malevarro/nodejs-goof`) | App Node/Express + MongoDB con dependencias y código vulnerables. | **SCA** (dependencias), **SAST** (código), **DAST** (app en ejecución con ZAP). |
| **AzureGoat** (`malevarro/AzureGoat`) | Infraestructura Azure vulnerable por diseño, desplegada con **Terraform** (App Functions, CosmosDB, Storage, Identities). | **SAST de IaC** (Terraform con Checkov/Trivy); **opcionalmente** despliegue en Azure para **DAST** y **CSPM**. |

---

## Entorno del laboratorio (sin VM/OVA)

```
  Equipo del estudiante (Windows)                 Azure (suscripción y red del Laboratorio 2)
  ┌───────────────────────────┐                   ┌──────────────────────────────────────────────┐
  │  Visual Studio Code + ext. │   navegador       │  Azure Cloud Shell  ──orquesta──►  ACI         │
  │  Git for Windows           │──────────────────►│                                                │
  │  Cliente Tailscale         │                   │  RG-Networking (Lab 2)                         │
  └─────────────┬─────────────┘                   │   Hub-VNet 10.0/16  ── Zentyal (NVA/egreso)     │
                │ Tailscale (WireGuard)            │   Spoke2-VNet 10.2/16                          │
                │ acceso a redes privadas          │   Spoke1-VNet 10.1/16                          │
                ▼                                   │    ├── WorkloadSubnet 10.1.0.0/24              │
        ┌───────────────┐   subnet router          │    │    └── VM-Spoke1  ◄── Tailscale subnet rtr │
        │  Tailnet       │◄────────────────────────┤    └── AciSubnet 10.1.3.0/24 (delegada ACI)    │
        └───────────────┘   anuncia 10.0/16,       │         ├── SonarQube (UI :9000) ◄─ Tailscale  │
                            10.1/16, 10.2/16       │         ├── nodejs-goof (app :3001) ◄─ Tailscale│
                                                   │         ├── Trivy / Checkov / ZAP (jobs)        │
   Reportes: Azure Files ◄── az storage download   │         └── reportes ─► Azure Files (share)     │
                                                   │   Egreso de ACI: UDR RT-Spoke1 → Zentyal (NAT)  │
                                                   └──────────────────────────────────────────────┘
```

- **Nada corre en Docker local.** Cada herramienta es un **container group** en ACI.
- Las ACI viven en una **subred delegada** dentro de la red del Lab 2; obtienen **IP privada** (ACI en VNet **no admite IP pública**), por lo que ZAP escanea la app por la **red privada**.
- **Egreso por Zentyal (sin NAT Gateway):** la `AciSubnet` usa la **UDR del Lab 2 (`RT-Spoke1`, `0.0.0.0/0 → Zentyal`)**, de modo que la salida a Internet de las ACI (pull de imágenes, bases de CVE) pasa por el firewall del laboratorio, igual que el resto de las cargas. *(Microsoft documenta el egreso de ACI a través de una UDR hacia un firewall/NVA; ver Referencias.)*
- **Acceso remoto con Tailscale:** la **VM-Spoke1** (ya desplegada en el Lab 2) actúa como *subnet router* y anuncia las redes privadas (`10.0.0.0/16`, `10.1.0.0/16`, `10.2.0.0/16`). El equipo del estudiante, con el cliente Tailscale, alcanza **cualquier IP privada** de la arquitectura, **incluidas las UIs de los ACI** (SonarQube `:9000`, la app `:3001`).
- Los **artefactos de reporte** (JSON/HTML) se escriben a **Azure Files** y se descargan; las **interfaces web** se consumen por **Tailscale**.
- La **construcción** de la imagen de la app se hace en la nube con **ACR Tasks** (`az acr build`) — sin Docker local.

---

## Métodos de análisis y mapa al OWASP Top 10:2025

| Método | Qué analiza | Herramienta (en ACI salvo el IDE) | OWASP Top 10:2025 |
|---|---|---|---|
| **SCA** | Dependencias e imágenes | Snyk (SaaS/IDE), **Trivy (ACI)** | **A03** Software Supply Chain Failures |
| **SAST** | Código fuente | SonarLint (IDE), **SonarQube (ACI)**, Qwiet | **A05** Injection, **A02** Misconfig, secretos |
| **SAST de IaC** | Terraform / Dockerfile | **Checkov (ACI)**, Trivy config | **A02** Security Misconfiguration |
| **Contenedores** | Imágenes (SO + libs) | **Trivy (ACI)** | **A03**, **A06** |
| **DAST** | App en ejecución | **OWASP ZAP (ACI)** | **A01**, **A05**, **A07** |
| **IAST** | App instrumentada | Agente (demostrativo) | **A01**, **A05** |

> Recordatorio: ningún método encuentra todo. **SAST/SCA** dan volumen y prevención temprana; **DAST/IAST** confirman lo explotable en runtime.

---

## Requisitos y preparación

### A. Cuentas en línea

1. Crea una cuenta en **GitHub** y haz **fork** de:
   - https://github.com/malevarro/nodejs-goof
   - https://github.com/malevarro/AzureGoat
2. Regístrate con **GitHub** en: [Snyk](https://app.snyk.io/login), [SonarCloud](https://sonarcloud.io/login) y [Qwiet AI](https://app.shiftleft.io/login).
3. En el equipo, instala **solo**: **Visual Studio Code** y **Git for Windows** (https://git-scm.com/download/win). No se instala Docker, ni Azure CLI, ni las herramientas de escaneo.
4. Acceso a **Azure Cloud Shell** (https://shell.azure.com) con la suscripción del Laboratorio 2 (rol Contributor sobre `RG-Networking`).

> Sustituye `<usuario-github>` por tu usuario y `<iniciales>` por tus iniciales en minúscula en todos los comandos.

### B. Preparar la red del Lab 2 para ACI

Ejecuta en **Azure Cloud Shell (Bash)**. Reutilizamos el `RG-Networking` y `Spoke1-VNet` del Laboratorio 2.

```bash
# --- Variables ---
export RG="RG-Networking"
export LOC="eastus"
export SPOKE1="Spoke1-VNet"
export INI="<iniciales>"
export GH="<usuario-github>"
export ACI_SUBNET="AciSubnet"
export SA="stlab3$INI"                 # Storage Account (único global, minúsculas)
export ACR="acrlab3$INI"               # Azure Container Registry (único global)

# --- 1. Subred delegada a ACI, con service endpoint de Storage ---
az network vnet subnet create \
  --resource-group $RG --vnet-name $SPOKE1 --name $ACI_SUBNET \
  --address-prefixes 10.1.3.0/24 \
  --delegations Microsoft.ContainerInstance/containerGroups \
  --service-endpoints Microsoft.Storage

# --- 2. Egreso de las ACI por Zentyal: asociar la UDR del Lab 2 (RT-Spoke1) ---
#     RT-Spoke1 ya contiene 0.0.0.0/0 → VirtualAppliance (IP privada de Zentyal).
#     Así el egreso de los ACI (pull de imágenes, bases de CVE) pasa por el firewall.
#     (No se usa NAT Gateway.)
az network vnet subnet update --resource-group $RG --vnet-name $SPOKE1 \
  --name $ACI_SUBNET --route-table RT-Spoke1

# --- 3. Storage Account + Azure Files para los reportes ---
az storage account create --resource-group $RG --name $SA \
  --sku Standard_LRS --min-tls-version TLS1_2
# Restringir el acceso de red a la subred de ACI (service endpoint)
az storage account network-rule add --resource-group $RG --account-name $SA \
  --vnet-name $SPOKE1 --subnet $ACI_SUBNET
export SA_KEY=$(az storage account keys list -g $RG -n $SA --query "[0].value" -o tsv)
az storage share create --account-name $SA --account-key "$SA_KEY" --name reports

# --- 4. Azure Container Registry (para construir la app sin Docker local) ---
az acr create --resource-group $RG --name $ACR --sku Basic --admin-enabled true
```

> **Diseño de red (validado con la documentación):** los ACI en una subred delegada **honran la UDR** de la subred; con `RT-Spoke1` (`0.0.0.0/0 → Zentyal`) el egreso sale **por el firewall del Lab 2**, sin NAT Gateway. El tráfico este-oeste (ZAP → app, scanner → SonarQube) permanece **privado dentro de la VNet**. Ver [ACI: egreso a través de un firewall/NVA por UDR](https://learn.microsoft.com/azure/container-instances/container-instances-egress-ip-address).
>
> **Requisitos para que el egreso por Zentyal funcione:**
> 1. En **Zentyal (Packet Filter)** deben estar permitidas las salidas de `10.1.0.0/16` a Internet en **80/443** (pull de imágenes desde `mcr.microsoft.com`, `ghcr.io`, `*.docker.io`, GitHub) y **53** (DNS). Las reglas del Lab 2 para los spokes ya cubren la `AciSubnet` (está dentro de `Spoke1-VNet 10.1.0.0/16`).
> 2. **DNS:** los ACI **no heredan el DNS de la VNet**. Si el pull de imágenes falla por resolución de nombres, especifica un resolver en el `az container create` con `--dns-name-servers 168.63.129.16` (Azure) o el que uses en el laboratorio.

### C. Acceso remoto a las redes privadas con Tailscale

Como los ACI y las VM **no tienen IP pública**, el estudiante accede a las redes privadas de la arquitectura mediante **Tailscale**: instala el cliente en su equipo y convierte a **VM-Spoke1** en un ***subnet router*** que anuncia las redes internas. Tailscale usa WireGuard y se conecta **hacia afuera** (a través de Zentyal), por lo que **no requiere abrir puertos de entrada**.

#### C.1 – Crear la cuenta de Tailscale

1. Ve a **https://login.tailscale.com/start** y regístrate (puedes usar tu cuenta de Google/Microsoft/GitHub). Se crea tu **tailnet** (red privada personal).
2. Abre la consola de administración en **https://login.tailscale.com/admin**.

#### C.2 – Instalar el cliente en el equipo del estudiante (Windows)

1. Descarga e instala Tailscale para Windows: **https://tailscale.com/download/windows**.
2. Inicia sesión con la misma cuenta del paso C.1. El equipo aparece como un dispositivo en tu tailnet.

#### C.3 – Instalar Tailscale en VM-Spoke1 y habilitarla como *subnet router*

Conéctate a **VM-Spoke1** (por SSH; recuerda que en el Lab 2 el acceso administrativo a las VMs es por la IP pública de Zentyal o el mecanismo que definiste). Dentro de VM-Spoke1 (Ubuntu):

```bash
# 1. Instalar Tailscale
curl -fsSL https://tailscale.com/install.sh | sh

# 2. Habilitar el reenvío de IP en el sistema operativo (necesario para el subnet router)
echo 'net.ipv4.ip_forward = 1'  | sudo tee -a /etc/sysctl.d/99-tailscale.conf
echo 'net.ipv6.conf.all.forwarding = 1' | sudo tee -a /etc/sysctl.d/99-tailscale.conf
sudo sysctl -p /etc/sysctl.d/99-tailscale.conf

# 3. Levantar Tailscale anunciando las redes privadas de la arquitectura del Lab 2
sudo tailscale up \
  --advertise-routes=10.0.0.0/16,10.1.0.0/16,10.2.0.0/16 \
  --accept-dns=false
# Sigue el enlace que imprime para autenticar la VM con tu cuenta de Tailscale.
```

> Las rutas anunciadas cubren el Hub (`10.0/16`), Spoke1 con su `AciSubnet` (`10.1/16`, incluye `10.1.3.0/24`) y Spoke2 (`10.2/16`). VM-Spoke1 alcanza Spoke1 y el Hub por *peering*, y Spoke2 a través de Zentyal (UDR `RT-Spoke1`), por lo que puede enrutar hacia **todas** las redes.

#### C.4 – Habilitar el reenvío de IP en Azure para VM-Spoke1

Para que VM-Spoke1 reenvíe tráfico que no es para ella (rol de router), Azure debe permitir *IP forwarding* en su NIC. Desde **Cloud Shell**:

```bash
NIC_SPOKE1=$(az vm show -g $RG -n VM-Spoke1 --query "networkProfile.networkInterfaces[0].id" -o tsv)
az network nic update --ids $NIC_SPOKE1 --ip-forwarding true
```

#### C.5 – Aprobar las rutas y aceptar en el equipo del estudiante

1. En la **consola de administración de Tailscale** (Machines → `VM-Spoke1` → **Edit route settings**), **aprueba** las subredes anunciadas (`10.0.0.0/16`, `10.1.0.0/16`, `10.2.0.0/16`).
2. En el **equipo del estudiante** (Windows), en el menú de Tailscale activa **“Use Tailscale subnets”** (equivale a `tailscale up --accept-routes`).

#### C.6 – Probar el acceso

Desde el equipo del estudiante, con Tailscale conectado:

```powershell
# Debe responder la VM-Spoke1 (u otra IP privada del Lab 2)
ping 10.1.0.4
```

Más adelante, cuando los ACI estén desplegados, podrás abrir en el navegador del equipo, por ejemplo, `http://<IP-privada-SonarQube>:9000` y `http://<IP-privada-app>:3001` — todo por la red privada, sin exponer nada a Internet.

### D. Clonar el código fuente al recurso compartido

En lugar de instalar git en cada contenedor de herramienta, un contenedor `alpine/git` clona los repos **una vez** al Azure Files; los demás contenedores lo leen montado.

```bash
az container create \
  --resource-group $RG \
  --name git-clone \
  --os-type Linux \
  --image alpine/git \
  --cpu 1 \
  --memory 1 \
  --restart-policy Never \
  --vnet $SPOKE1 \
  --subnet $ACI_SUBNET \
  --azure-file-volume-account-name $SA \
  --azure-file-volume-account-key "$SA_KEY" \
  --azure-file-volume-share-name reports \
  --azure-file-volume-mount-path /reports \
  --command-line "sh -ec 'rm -rf /reports/src && \
                         mkdir -p /reports/src && \
                         git clone https://github.com/$GH/nodejs-goof /reports/src/nodejs-goof && \
                         git clone https://github.com/$GH/AzureGoat /reports/src/AzureGoat && \
                         echo CLONADO'"

# Ver el resultado y esperar a que termine (Succeeded)
az container logs --resource-group $RG --name git-clone
az container show  --resource-group $RG --name git-clone --query "containers[0].instanceView.currentState.state" -o tsv
az container delete --resource-group $RG --name git-clone --yes
```

---

## Parte 1 – Análisis en línea de los repositorios (SaaS)

Integra cada herramienta con GitHub y analiza tus forks (**SCA/SAST en el repositorio**, sin instalar nada).

### 1.1 – Snyk
1. Ingresa a [Snyk](https://app.snyk.io/login) con GitHub → integra GitHub → selecciona `nodejs-goof` y `AzureGoat` → **Add selected repositories**.
2. Revisa **Projects**: severidad, CVE, dependencia afectada y versión que corrige. Dependencias vulnerables = **A03**.

### 1.2 – SonarCloud
1. Ingresa a [SonarCloud](https://sonarcloud.io/login) con GitHub → integra el repositorio.
2. En **My Projects → Main Branch**: Security Hotspots, Bugs, Code Smells. Inyección/manejo de datos = **A05/A02**.

### 1.3 – Qwiet AI (ShiftLeft)
1. Ingresa a [Qwiet AI](https://qwiet.ai/) con GitHub → integra el repositorio.
2. En **Applications** revisa el árbol de flujo de datos (de la fuente no confiable al *sink*).

---

## Parte 2 – Análisis en el IDE (Visual Studio Code)

Inspección **mientras codificas** (shift-left). Es la **única** ejecución local, mediante extensiones que se autoconfiguran (no requieren instalar motores por separado).

### 2.1 – Clonar los repos en el equipo (con Git for Windows)
```powershell
git clone https://github.com/<usuario-github>/nodejs-goof.git
git clone https://github.com/<usuario-github>/AzureGoat.git
```

### 2.2 – Instalar extensiones en VS Code
En **Extensions** busca e instala:
1. **Snyk Security**  2. **Trivy** (Aqua)  3. **SonarQube for IDE** (SonarLint)  4. **Checkov** (Prisma)  5. **Qwiet preZero**

> Abre en VS Code **solo la carpeta** del repo que analizarás en el momento (workspace acotado). Inicia sesión en GitHub/Snyk/SonarCloud/Qwiet en el navegador para que las extensiones autentiquen.

### 2.3 – Activar y revisar
- **Snyk:** *Trust workspace and connect* → *Authenticate* → revisa Open Source / Code / IaC.
- **SonarLint:** conéctalo a SonarCloud (o al SonarQube de la Parte 5 en *connected mode*).
- **Checkov:** abre un `.tf` de AzureGoat o el `Dockerfile` → `Ctrl+Shift+P` → **Checkov scan**.
- **Trivy / Qwiet:** ejecuta desde su panel/paleta.
- Los hallazgos sin panel propio aparecen en **Problems** (abajo a la izquierda); clic para saltar a la línea de código.

---

## Parte 3 – SCA y contenedores con Trivy en ACI

Trivy corre como **contenedor en ACI**, escanea imágenes y el código clonado en el share, y escribe reportes JSON a Azure Files.

```bash
# 3.1 – SCA de una imagen de contenedor
az container create --resource-group $RG --name trivy-image \
  --image acrlab3mavr.azurecr.io/trivy:latest --restart-policy Never --os-type Linux \
  --registry-username acrlab3mavr \
  --cpu 1 \
  --memory 1 \
  --vnet $SPOKE1 --subnet $ACI_SUBNET \
  --azure-file-volume-account-name $SA --azure-file-volume-account-key "$SA_KEY" \
  --azure-file-volume-share-name reports --azure-file-volume-mount-path /reports \
  --command-line "sh -c 'trivy image --format json --output /reports/trivy-node6.json node:6-stretch'"

az container logs -g $RG -n trivy-image     # progreso
az container delete -g $RG -n trivy-image --yes

# 3.2 – SCA del filesystem del proyecto (dependencias + secretos) sobre el código clonado
# Salida en formato JSON
az container create --resource-group $RG --name trivy-image \
  --image acrlab3mavr.azurecr.io/trivy:latest --restart-policy Never --os-type Linux \
  --registry-username acrlab3mavr \
  --cpu 1 \
  --memory 1 \
  --vnet $SPOKE1 --subnet $ACI_SUBNET \
  --azure-file-volume-account-name $SA --azure-file-volume-account-key "$SA_KEY" \
  --azure-file-volume-share-name reports --azure-file-volume-mount-path /reports \
  --command-line "sh -c 'trivy repo --format json --output /reports/trivy-nodejsgoof.json https://github.com/malevarro/nodejs-goof'"

# Salida en una tabla de texto
az container create --resource-group $RG --name trivy-image \
  --image acrlab3mavr.azurecr.io/trivy:latest --restart-policy Never --os-type Linux \
  --registry-username acrlab3mavr \
  --cpu 1 \
  --memory 1 \
  --vnet $SPOKE1 --subnet $ACI_SUBNET \
  --azure-file-volume-account-name $SA --azure-file-volume-account-key "$SA_KEY" \
  --azure-file-volume-share-name reports --azure-file-volume-mount-path /reports \
  --command-line "sh -c 'trivy repo --format table --output /reports/trivy-nodejsgoof.txt https://github.com/malevarro/nodejs-goof'"  

# Salida en formato de reporte SARIF
az container create --resource-group $RG --name trivy-image \
  --image acrlab3mavr.azurecr.io/trivy:latest --restart-policy Never --os-type Linux \
  --registry-username acrlab3mavr \
  --cpu 1 \
  --memory 1 \
  --vnet $SPOKE1 --subnet $ACI_SUBNET \
  --azure-file-volume-account-name $SA --azure-file-volume-account-key "$SA_KEY" \
  --azure-file-volume-share-name reports --azure-file-volume-mount-path /reports \
  --command-line "sh -c 'trivy repo --format sarif --output /reports/trivy-nodejsgoof.sarif https://github.com/malevarro/nodejs-goof'"

# Análisis del repositorio AzureGoat
az container create --resource-group $RG --name trivy-image \
  --image acrlab3mavr.azurecr.io/trivy:latest --restart-policy Never --os-type Linux \
  --registry-username acrlab3mavr \
  --cpu 1 \
  --memory 1 \
  --vnet $SPOKE1 --subnet $ACI_SUBNET \
  --azure-file-volume-account-name $SA --azure-file-volume-account-key "$SA_KEY" \
  --azure-file-volume-share-name reports --azure-file-volume-mount-path /reports \
  --command-line "sh -c 'trivy repo --format sarif --output /reports/trivy-AzureGoat.sarif https://github.com/malevarro/AzureGoat'"
```

**Analiza** (descargando los JSON, ver [Recoger los reportes](#recoger-los-reportes-desde-azure-files)): 3 CVE HIGH/CRITICAL y su versión de corrección. ¿Cuáles vienen de la imagen base y cuáles de las dependencias? → **A03**.

---

## Parte 4 – SAST de IaC con Checkov en ACI

AzureGoat está definido en **Terraform**: objetivo ideal para escaneo de IaC. Checkov corre como ACI sobre el código clonado.

```bash
az container create --resource-group $RG --name checkov-azuregoat \
  --image acrlab3mavr.azurecr.io/checkov:latest --restart-policy Never \
  --vnet $SPOKE1 --subnet $ACI_SUBNET \
  --registry-username acrlab3mavr \
  --os-type Linux \
  --cpu 1 \
  --memory 1 \
  --azure-file-volume-account-name $SA --azure-file-volume-account-key "$SA_KEY" \
  --azure-file-volume-share-name reports --azure-file-volume-mount-path /reports \
  --command-line "sh -c 'checkov -d /reports/src/nodejs-goof -o sarif --output-file-path /reports/checkov-azuregoat || true'"

az container logs -g $RG -n checkov-azuregoat
az container delete -g $RG -n checkov-azuregoat --yes

# Análisis del segundo repositorio
az container create --resource-group $RG --name checkov-azuregoat \
  --image acrlab3mavr.azurecr.io/checkov:latest --restart-policy Never \
  --vnet $SPOKE1 --subnet $ACI_SUBNET \
  --registry-username acrlab3mavr \
  --os-type Linux \
  --cpu 1 \
  --memory 1 \
  --azure-file-volume-account-name $SA --azure-file-volume-account-key "$SA_KEY" \
  --azure-file-volume-share-name reports --azure-file-volume-mount-path /reports \
  --command-line "sh -c 'checkov -d /reports/src/nodejs-goof -o sarif --output-file-path /reports/checkov-nodejs-goof || true'"

az container logs -g $RG -n trivy-iac
az container delete -g $RG -n trivy-iac --yes
```

**Analiza y clasifica** 5+ hallazgos del Terraform (la mayoría **A02 Security Misconfiguration**; algunos **A04** por cifrado ausente, **A01** por accesos públicos). Es el **shift-left aplicado a la nube**: atrapas en el código lo que en las Sesiones 1 y 2 detectabas *después* con CSPM.

---

## Parte 6 – DAST con OWASP ZAP en ACI

Ponemos la app a correr **como ACI** y la atacamos desde otro **ACI con OWASP ZAP**, todo por la **red privada** del Lab 2.

### 6.1 – Construir la imagen de la app sin Docker local (ACR Tasks)
```bash
# ACR construye la imagen directamente desde tu repo de GitHub (en la nube)
az acr build --registry $ACR --image nodejs-goof:latest \
  https://github.com/$GH/nodejs-goof.git
export ACR_SERVER=$(az acr show -n $ACR --query loginServer -o tsv)
export ACR_USER=$(az acr credential show -n $ACR --query username -o tsv)
export ACR_PASS=$(az acr credential show -n $ACR --query "passwords[0].value" -o tsv)
```

### 6.2 – Desplegar MongoDB y la app en la red privada
```bash
# Mongo (imagen pública)
az container create --resource-group $RG --name goof-mongo \
  --image mongo:5 --restart-policy Always --ports 27017 \
  --vnet $SPOKE1 --subnet $ACI_SUBNET
export MONGO_IP=$(az container show -g $RG -n goof-mongo --query "ipAddress.ip" -o tsv)

# App nodejs-goof desde el ACR privado, apuntando a Mongo por IP privada
az container create --resource-group $RG --name goof-app \
  --image "$ACR_SERVER/nodejs-goof:latest" --restart-policy Always --ports 3001 \
  --registry-login-server $ACR_SERVER --registry-username $ACR_USER --registry-password "$ACR_PASS" \
  --vnet $SPOKE1 --subnet $ACI_SUBNET \
  --environment-variables MONGODB="mongodb://$MONGO_IP:27017/todos"
export APP_IP=$(az container show -g $RG -n goof-app --query "ipAddress.ip" -o tsv)
echo "App privada (por Tailscale) en: http://$APP_IP:3001"
```

> El nombre de la variable de conexión (`MONGODB`) puede variar según el repo; verifica el `README`/`docker-compose` de nodejs-goof y ajústalo.
>
> **Acceso manual por Tailscale:** con Tailscale conectado puedes abrir `http://$APP_IP:3001` en el navegador del equipo para explorar la app vulnerable manualmente antes o después del escaneo DAST.

### 6.3 – Ejecutar OWASP ZAP (baseline) contra la app privada
```bash
az container create --resource-group $RG --name zap-scan \
  --image ghcr.io/zaproxy/zaproxy:stable --restart-policy Never \
  --vnet $SPOKE1 --subnet $ACI_SUBNET \
  --azure-file-volume-account-name $SA --azure-file-volume-account-key "$SA_KEY" \
  --azure-file-volume-share-name reports --azure-file-volume-mount-path /zap/wrk \
  --command-line "zap-baseline.py -t http://$APP_IP:3001 -r zap-report.html"

az container logs -g $RG -n zap-scan          # resumen WARN/FAIL por regla
az container delete -g $RG -n zap-scan --yes
```

Descarga `zap-report.html` desde Azure Files. Hallazgos típicos: cabeceras ausentes (CSP, X-Frame-Options), cookies sin `HttpOnly/Secure`, XSS reflejado → **A05/A02/A07**.

**Compara SAST vs DAST:** ¿un mismo problema (p. ej. XSS) lo vieron SonarQube (línea de código, posible falso positivo) y ZAP (confirmado en runtime)? ¿Por qué cada uno lo ve distinto?

---

## Parte 7 – IAST (concepto y demostración)

El **IAST** instrumenta la app con un **agente** dentro del proceso durante las pruebas: combina la visibilidad del código (SAST) con la ejecución real (DAST), señalando la **línea exacta** de una vulnerabilidad **confirmada en runtime**.

Demostración conceptual: al construir la imagen (Parte 6.1) se podría añadir un **agente IAST** al arranque de Node (`node -r <agente> app.js`). Mientras ZAP recorre la app, el agente correlaciona cada petición externa con la línea de código de la llamada peligrosa (query SQL, comando, deserialización) y la reporta con muy pocos falsos positivos.

**Discusión:** ¿en qué fase del pipeline encaja IAST? ¿Por qué reduce falsos positivos frente a SAST puro? ¿Qué requiere que SAST no necesita? (instrumentar el runtime).

---

## Parte 8 – AzureGoat: despliegue opcional en Azure

> ⚠️ **Solo con autorización, suscripción propia y consciente del costo.** AzureGoat es **vulnerable por diseño**: no lo dejes desplegado. Bórralo al terminar.

El análisis estático de su IaC ya se hizo en la Parte 4. Para practicar DAST/CSPM sobre infraestructura real, desde **Azure Cloud Shell** (trae Terraform):

```bash
az group create --name azuregoat_app --location $LOC
cd ~ && git clone https://github.com/$GH/AzureGoat.git && cd AzureGoat
terraform init
terraform apply --auto-approve      # imprime la URL de la app desplegada
```

- **DAST sobre AzureGoat:** repite la Parte 6.3 cambiando `-t` por la URL pública que devolvió Terraform (ZAP en ACI la alcanza por su egreso a través de Zentyal).
- **CSPM:** audita la infraestructura con **Prowler** (Sesión 1) o **CloudSploit** (Sesión 2) desde Cloud Shell. Contrasta: lo que Checkov atrapó *antes* de desplegar no debería reaparecer si se hubiera corregido — demostración del valor del shift-left.

**Destruir (obligatorio):**
```bash
cd ~/AzureGoat && terraform destroy --auto-approve
az group delete --name azuregoat_app --yes --no-wait
```

---

## Recoger los reportes y acceder a las UIs

Hay **dos vías de acceso**, complementarias:

**1. Artefactos de reporte (JSON/HTML) → Azure Files.** Los reportes de Trivy, Checkov y ZAP quedan en el share `reports`:

```bash
# Listar
az storage file list --account-name $SA --account-key "$SA_KEY" --share-name reports -o table

# Descargar uno
az storage file download --account-name $SA --account-key "$SA_KEY" \
  --share-name reports --path zap-report.html --dest ./zap-report.html
```

O desde el **portal**: Storage Account `stlab3<iniciales>` → **File shares → reports** → **Download**. (En Cloud Shell, `download` deja el archivo en tu unidad de Cloud Shell; usa **Manage files → Download** para bajarlo al equipo.)

**2. Interfaces web (SonarQube, la app) → Tailscale.** Con el cliente Tailscale conectado (Sección C), abre directamente en el navegador del equipo, por su **IP privada**:

- App nodejs-goof: `http://<IP-privada-app>:3001`

Obtén esas IPs con `az container show -g $RG -n <nombre> --query ipAddress.ip -o tsv`. No hay ninguna IP pública ni exposición a Internet: el acceso viaja cifrado por el *subnet router* de VM-Spoke1.

---

## Remediación y re-escaneo

Cierra el ciclo **hallazgo → corrección → verificación** con al menos un ejemplo por método. Corriges en tu **fork** (con Git for Windows / VS Code) y vuelves a lanzar el ACI correspondiente.

| Método | Corrección de ejemplo | Verificación (re-lanzar ACI) |
|---|---|---|
| **SCA** | En `nodejs-goof`, actualiza una dependencia vulnerable en `package.json`. | Re-ejecutar `git-clone` + `trivy-fs`: menos CVE. |
| **SAST** | Parametrizar una consulta o corregir un *hotspot* de SonarQube. | Re-ejecutar `sonar-runner` y revisar en la UI de SonarQube (por Tailscale). |
| **IaC (AzureGoat)** | Forzar cifrado/https o cerrar un acceso público en el `.tf`. | Re-ejecutar `checkov-azuregoat`: menos políticas fallidas. |
| **DAST** | Añadir cabeceras de seguridad en la app; reconstruir con `az acr build`. | Redeploy `goof-app` + re-ejecutar `zap-scan`: menos WARN. |

> **Criterio:** documenta qué **remediaste**, qué **mitigaste** y qué **aceptaste** con justificación (gestión de riesgos, Sesión 1).

**Entregable:** un PDF con (1) un hallazgo por método con captura del reporte, (2) su categoría OWASP Top 10:2025, (3) la corrección y el re-escaneo, y (4) un párrafo comparando SAST vs DAST.

---

## Limpieza

```bash
# Contenedores de larga duración
az container delete -g $RG -n sonarqube --yes
az container delete -g $RG -n goof-app --yes
az container delete -g $RG -n goof-mongo --yes

# Red y almacenamiento del lab
az network vnet subnet update -g $RG --vnet-name $SPOKE1 -n $ACI_SUBNET --route-table "" 2>/dev/null
az network vnet subnet delete -g $RG --vnet-name $SPOKE1 -n $ACI_SUBNET
az storage account delete -g $RG -n $SA --yes
az acr delete -g $RG -n $ACR --yes

# AzureGoat, si lo desplegaste (Parte 8)
# cd ~/AzureGoat && terraform destroy --auto-approve && az group delete --name azuregoat_app --yes
```

**Tailscale (opcional, para dejar todo como estaba):**
```bash
# En VM-Spoke1: dejar de anunciar rutas y desconectar
sudo tailscale down
# (opcional) desinstalar: sudo apt-get remove -y tailscale
```
En la **consola de administración de Tailscale** elimina los dispositivos `VM-Spoke1` y el equipo del estudiante si ya no los usarás. En Azure puedes revertir el *IP forwarding* de la NIC de VM-Spoke1 con `az network nic update --ids $NIC_SPOKE1 --ip-forwarding false`.

> No borres los recursos base del Laboratorio 2 (Zentyal, VNets, peering, `RT-Spoke1`) salvo que ya no los necesites.

---

## Checklist de finalización

**Preparación**
- [ ] Equipo con **solo** VS Code (+ extensiones), Git for Windows y cliente Tailscale.
- [ ] Forks de nodejs-goof y AzureGoat; cuentas Snyk/SonarCloud/Qwiet; cuenta Tailscale.
- [ ] Subred `AciSubnet` delegada + **UDR `RT-Spoke1` asociada (egreso por Zentyal)** + Storage/Azure Files + ACR en la red del Lab 2.
- [ ] **Tailscale:** cliente en el equipo; VM-Spoke1 como *subnet router* (rutas anunciadas y aprobadas); IP forwarding en la NIC de VM-Spoke1; rutas aceptadas en el equipo; `ping` a una IP privada OK.
- [ ] Código clonado al share (`git-clone` ACI).

**Análisis (todo en ACI, salvo el IDE)**
- [ ] Parte 1 – Snyk/SonarCloud/Qwiet en el repositorio.
- [ ] Parte 2 – Extensiones de VS Code mostrando hallazgos.
- [ ] Parte 3 – **Trivy en ACI** (imagen + fs); reportes en Azure Files.
- [ ] Parte 4 – **Checkov/Trivy en ACI** sobre el Terraform de AzureGoat (5+ hallazgos clasificados).
- [ ] Parte 5 – **SonarQube servidor en ACI** + sonar-scanner; UI revisada **por Tailscale**.
- [ ] Parte 6 – App construida con `az acr build`, desplegada en ACI, accesible **por Tailscale**, y **OWASP ZAP en ACI** ejecutado.
- [ ] Parte 7 – IAST explicado/demostrado.

**Opcional / avanzado**
- [ ] Parte 8 – AzureGoat desplegado (Terraform), DAST/CSPM, y **destruido**.

**Cierre**
- [ ] Una vulnerabilidad remediada por método y re-escaneada.
- [ ] Cada hallazgo mapeado al OWASP Top 10:2025.
- [ ] Entregable (PDF) con hallazgos, correcciones y comparación SAST vs DAST.
- [ ] **Limpieza** de ACI, storage, ACR, subred y sesión de Tailscale.

---

## Solución de problemas frecuentes

| Síntoma | Causa probable | Solución |
|---|---|---|
| `az container create` falla por la subred | La subred no está delegada o tiene otros recursos | La `AciSubnet` debe estar delegada a `Microsoft.ContainerInstance/containerGroups` y contener **solo** ACI |
| La ACI no arranca / no baja la imagen | Egreso o DNS | Confirmar que `RT-Spoke1` está asociada a `AciSubnet` y que **Zentyal permite 80/443/53** desde `10.1.0.0/16`; si falla la resolución, añadir `--dns-name-servers 168.63.129.16` al `az container create` |
| La ACI no monta Azure Files | Falta el service endpoint / regla de red | La subred debe tener `--service-endpoints Microsoft.Storage` y la cuenta la regla de red hacia esa subred |
| **SonarQube** no queda *operational* | Elasticsearch requiere `vm.max_map_count` (no ajustable en ACI) | Usar el **fallback a SonarCloud** (scanner en ACI, servidor SaaS) con `SONAR_HOST_URL="https://sonarcloud.io"` |
| ZAP no alcanza la app | IP privada incorrecta o app caída | `az container show -n goof-app --query ipAddress.ip`; revisar `az container logs -n goof-app` |
| `az acr build` falla | Repo privado o Dockerfile ausente | Usar tu fork público; verificar que el repo tenga `Dockerfile` en la raíz |
| **Tailscale no conecta desde VM-Spoke1** | Egreso bloqueado por Zentyal | Tailscale sale por 443 (DERP relay); asegúrate de permitir 443 saliente en Zentyal. Para conexión directa, permitir UDP 41641 saliente (opcional) |
| **No accedo a las IP privadas por Tailscale** | Rutas no aprobadas o no aceptadas | Aprobar las subredes en la consola de Tailscale (Machines → VM-Spoke1 → route settings) y activar “Use Tailscale subnets” en el equipo |
| El *subnet router* no reenvía | Falta IP forwarding (Azure u OS) | `az network nic update ... --ip-forwarding true` **y** `net.ipv4.ip_forward=1` en VM-Spoke1 |
| No veo los reportes | Se descargan en Cloud Shell, no en el equipo | `az storage file download` y luego **Manage files → Download**, o bajarlos del portal |
| ACI en VNet sin IP pública | Es el comportamiento esperado | ACI en VNet **no admite IP pública**; el acceso a UIs es por **Tailscale**, no por Internet |

---

## Referencias

- Guía base (DevSecOps-Lab): https://github.com/malevarro/DevSecOps-Lab/blob/master/Laborarotio%202.md
- Apps: https://github.com/malevarro/nodejs-goof · https://github.com/malevarro/AzureGoat
- OWASP Top 10:2025 — https://owasp.org/Top10/2025/
- ACI en una red virtual: https://learn.microsoft.com/azure/container-instances/container-instances-vnet
- **ACI: egreso a través de un firewall/NVA con UDR**: https://learn.microsoft.com/azure/container-instances/container-instances-egress-ip-address
- ACI + Azure Files (volúmenes): https://learn.microsoft.com/azure/container-instances/container-instances-volume-azure-files
- **Tailscale — subnet routers**: https://tailscale.com/kb/1019/subnets
- **Tailscale — descarga del cliente**: https://tailscale.com/download
- Tailscale en un servidor Linux (Ubuntu): https://tailscale.com/kb/1031/install-linux
- ACR Tasks (`az acr build`): https://learn.microsoft.com/azure/container-registry/container-registry-quickstart-task-cli
- OWASP ZAP (Docker): https://www.zaproxy.org/docs/docker/baseline-scan/
- SonarQube (imagen): https://hub.docker.com/_/sonarqube · Trivy: https://trivy.dev/ · Checkov: https://www.checkov.io/
- Snyk: https://snyk.io/ · Qwiet AI: https://qwiet.ai/
- Azure Cloud Shell: https://learn.microsoft.com/azure/cloud-shell/overview
