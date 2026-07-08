# Guía de Laboratorio — Sesión 4
## WAF con Azure Application Gateway sobre DVWA, y pipeline de CI/CD (5 escáneres) con GitHub Actions hacia Azure App Service

> **Curso:** SecOps — Seguridad de Aplicaciones y DevSecOps
> **Docente:** Manuel Alejandro Vargas Rojas — manuelvargasrojas@cedoc.edu.co
> **Nivel:** Posgrado · **Uso:** interno
> **Base:** continúa la **DVWA** desplegada en el Laboratorio de la **Sesión 3** (imagen `web-dvwa`, puerto 80) y la red del **Laboratorio 2** (`RG-Networking`, Hub & Spoke con Zentyal).

Este laboratorio tiene dos partes que materializan la teoría de la Sesión 4:

- **Parte A — Protección con WAF:** desplegar un **Azure Application Gateway con Web Application Firewall (WAF_v2)** delante de la **DVWA** de la Sesión 3 y **cargar una política (OWASP CRS)** que **bloquee** los ataques que ejecutaste manualmente en la Sesión 3 — **SQL Injection** y **Command Injection**.
- **Parte B — CI/CD con seguridad:** configurar, paso a paso, un **pipeline de GitHub Actions** que ejecute **SonarCloud, Qwiet, Snyk, Trivy y Checkov** como *gates* de seguridad y **despliegue** la aplicación a un **Azure App Service** (autenticación **sin secretos** mediante **OIDC**).

---

## Tabla de contenido

- [Objetivo](#objetivo)
- [Requisitos y variables](#requisitos-y-variables)
- [PARTE A – Application Gateway con WAF sobre DVWA](#parte-a--application-gateway-con-waf-sobre-dvwa)
  - [A.1 – Confirmar la DVWA de la Sesión 3](#a1--confirmar-la-dvwa-de-la-sesión-3)
  - [A.2 – Subred e IP pública del Application Gateway](#a2--subred-e-ip-pública-del-application-gateway)
  - [A.3 – Crear la política de WAF (OWASP CRS)](#a3--crear-la-política-de-waf-owasp-crs)
  - [A.4 – Crear el Application Gateway WAF_v2 con backend a DVWA](#a4--crear-el-application-gateway-waf_v2-con-backend-a-dvwa)
  - [A.5 – NSG del Application Gateway y sondeo de estado](#a5--nsg-del-application-gateway-y-sondeo-de-estado)
  - [A.6 – Probar el bloqueo: SQL Injection y Command Injection](#a6--probar-el-bloqueo-sql-injection-y-command-injection)
- [PARTE B – Pipeline de CI/CD con GitHub Actions hacia App Service](#parte-b--pipeline-de-cicd-con-github-actions-hacia-app-service)
  - [B.1 – Preparar el repositorio (fork de DVWA)](#b1--preparar-el-repositorio-fork-de-dvwa)
  - [B.2 – Crear el App Service y el registro de contenedores](#b2--crear-el-app-service-y-el-registro-de-contenedores)
  - [B.3 – Autenticación sin secretos: OIDC (federated credential)](#b3--autenticación-sin-secretos-oidc-federated-credential)
  - [B.4 – Cargar los secretos en GitHub](#b4--cargar-los-secretos-en-github)
  - [B.5 – El workflow completo (5 escáneres + build + deploy)](#b5--el-workflow-completo-5-escáneres--build--deploy)
  - [B.6 – Ejecutar y revisar los gates](#b6--ejecutar-y-revisar-los-gates)
  - [B.7 – (Opcional) Proteger el App Service con el WAF](#b7--opcional-proteger-el-app-service-con-el-waf)
- [Limpieza](#limpieza)
- [Checklist de finalización](#checklist-de-finalización)
- [Solución de problemas frecuentes](#solución-de-problemas-frecuentes)
- [Referencias](#referencias)

---

## Objetivo

Al finalizar, el estudiante será capaz de:

- Desplegar un **Application Gateway WAF_v2** y asociarle una **política WAF** con el **OWASP Core Rule Set** en modo **Prevention**.
- Verificar que el WAF **bloquea (HTTP 403)** los ataques de **SQL Injection** y **Command Injection** que en la Sesión 3 tuvieron éxito directamente sobre DVWA.
- Configurar un **pipeline de GitHub Actions** con **cinco herramientas de análisis** (SonarCloud, Qwiet, Snyk, Trivy, Checkov) como pasos/gate del pipeline.
- Autenticarse a Azure **sin secretos de larga vida** usando **OIDC** y **desplegar** la aplicación a **Azure App Service** desde el pipeline.

---

## Requisitos y variables

- La **red del Laboratorio 2** (`RG-Networking`, `Hub-VNet 10.0.0.0/16`, `Spoke1-VNet 10.1.0.0/16`, peering Hub↔Spoke1) y la **DVWA de la Sesión 3** corriendo como ACI (`web-dvwa`, puerto 80) en la `AciSubnet` (10.1.3.0/24).
- **Azure CLI / Cloud Shell** con rol **Owner** o **Contributor + User Access Administrator** sobre `RG-Networking` (para crear el App Gateway y la federación OIDC).
- **Cuenta de GitHub** y cuentas (registro con GitHub) en **SonarCloud**, **Snyk** y **Qwiet AI** (de la Sesión 3). **Trivy** y **Checkov** no requieren cuenta.
- **Git for Windows** (o edición web de GitHub).

```bash
# --- Variables (ajusta <iniciales> y <usuario-github>) ---
export RG="RG-Networking"
export LOC="eastus"
export INI="<iniciales>"
export GH="<usuario-github>"
export HUB="Hub-VNet"
export SPOKE1="Spoke1-VNet"
export ACR="acrlab3$INI"                       # el ACR de la Sesión 3
export APPGW="appgw-waf-$INI"
export WAF_POLICY="wafpol-dvwa-$INI"
export APPGW_SUBNET="AppGwSubnet"
export APP_PLAN="plan-dvwa-$INI"
export WEBAPP="app-dvwa-$INI"                   # App Service (único global)
export SUB_ID=$(az account show --query id -o tsv)
export TENANT_ID=$(az account show --query tenantId -o tsv)
```

---

# PARTE A – Application Gateway con WAF sobre DVWA

Pondremos un **WAF** en la ruta de entrada a DVWA. El tráfico pasará: **Internet → Application Gateway (WAF) → DVWA (ACI privada, puerto 80)**. Con el WAF en **Prevention**, los ataques de la Sesión 3 serán **bloqueados** antes de llegar a la aplicación.

```
Internet ──► [ Application Gateway WAF_v2 ]  (IP pública, política OWASP CRS)
                     │  backend
                     ▼
             DVWA (web-dvwa) — ACI privada 10.1.3.x : 80   (Spoke1, red del Lab 2)
```

## A.1 – Confirmar la DVWA de la Sesión 3

Verifica que la DVWA de la Sesión 3 está corriendo y toma su **IP privada** (será el *backend* del App Gateway):

```bash
export DVWA_IP=$(az container show -g $RG -n web-dvwa --query "ipAddress.ip" -o tsv)
echo "DVWA backend (IP privada): $DVWA_IP"
```

> Si la borraste tras la Sesión 3, vuelve a desplegarla con el mismo comando de la Sesión 3 (imagen `acrlab3$INI.azurecr.io/web-dvwa:latest`, puerto 80, en la `AciSubnet`). Recuerda entrar una vez (por Tailscale) y pulsar **Create / Reset Database** y fijar el nivel **DVWA Security = low** para poder reproducir los ataques.

## A.2 – Subred e IP pública del Application Gateway

El Application Gateway exige una **subred dedicada** (solo para él). La creamos en el **Hub** (tiene línea de vista a DVWA por el *peering* Hub↔Spoke1).

```bash
# Subred dedicada del App Gateway (espacio libre en el Hub 10.0.0.0/16)
az network vnet subnet create \
  --resource-group $RG --vnet-name $HUB --name $APPGW_SUBNET \
  --address-prefixes 10.0.2.0/24

# IP pública estándar para el frontend del App Gateway
az network public-ip create \
  --resource-group $RG --name "${APPGW}-pip" \
  --sku Standard --allocation-method Static
```

## A.3 – Crear la política de WAF (OWASP CRS)

Creamos la **política de WAF** con el **OWASP Core Rule Set 3.2** (incluye las reglas contra **SQL Injection – grupo 942xxx** y **Remote Command Execution / Command Injection – grupo 932xxx**) y la ponemos en **Prevention** (bloquea, no solo registra).

```bash
# 1. Crear la política con el conjunto OWASP CRS 3.2
az network application-gateway waf-policy create \
  --resource-group $RG --name $WAF_POLICY \
  --type OWASP --version 3.2

# 2. Ponerla en modo Prevention y habilitada
az network application-gateway waf-policy policy-setting update \
  --policy-name $WAF_POLICY --resource-group $RG \
  --mode Prevention --state Enabled

# 3. (Verificación) ver el conjunto de reglas administradas
az network application-gateway waf-policy managed-rule rule-set list \
  --policy-name $WAF_POLICY --resource-group $RG -o table

export WAF_POLICY_ID=$(az network application-gateway waf-policy show \
  -g $RG -n $WAF_POLICY --query id -o tsv)
```

> **Sugerencia didáctica:** puedes empezar en modo **Detection** (`--mode Detection`) para *observar* en los logs cómo el WAF **detecta** los ataques sin bloquearlos, y luego cambiar a **Prevention** para ver el **bloqueo (403)**. Es la mejor forma de mostrar la diferencia.

## A.4 – Crear el Application Gateway WAF_v2 con backend a DVWA

```bash
az network application-gateway create \
  --resource-group $RG --name $APPGW \
  --location $LOC \
  --sku WAF_v2 --capacity 1 \
  --vnet-name $HUB --subnet $APPGW_SUBNET \
  --public-ip-address "${APPGW}-pip" \
  --servers $DVWA_IP \
  --frontend-port 80 \
  --http-settings-port 80 \
  --http-settings-protocol Http \
  --waf-policy $WAF_POLICY_ID \
  --priority 100
```

> La creación tarda varios minutos. Al terminar quedan un *backend pool* (con la IP de DVWA), un *listener* en el puerto 80, la *HTTP setting* al 80 y la *rule* por defecto, todo con la **política WAF** asociada.

Obtén la **IP pública** del App Gateway (será la URL por la que entrarás a DVWA con protección):

```bash
export APPGW_PIP=$(az network public-ip show -g $RG -n "${APPGW}-pip" --query ipAddress -o tsv)
echo "DVWA protegida por WAF en: http://$APPGW_PIP/"
```

## A.5 – NSG del Application Gateway y sondeo de estado

La subred del App Gateway necesita permitir el tráfico entrante de Internet (puerto 80) y el de **gestión del propio servicio** (rango `GatewayManager`).

```bash
az network nsg create -g $RG -n "nsg-$APPGW_SUBNET"

# Tráfico entrante de gestión del App Gateway (obligatorio para WAF_v2)
az network nsg rule create -g $RG --nsg-name "nsg-$APPGW_SUBNET" \
  --name Allow-GatewayManager --priority 100 --direction Inbound --access Allow \
  --protocol Tcp --source-address-prefixes GatewayManager \
  --source-port-range '*' --destination-address-prefix '*' --destination-port-range 65200-65535

# HTTP entrante desde Internet
az network nsg rule create -g $RG --nsg-name "nsg-$APPGW_SUBNET" \
  --name Allow-HTTP-Internet --priority 110 --direction Inbound --access Allow \
  --protocol Tcp --source-address-prefix Internet \
  --source-port-range '*' --destination-address-prefix '*' --destination-port-range 80

# Asociar el NSG a la subred del App Gateway
az network vnet subnet update -g $RG --vnet-name $HUB --name $APPGW_SUBNET \
  --network-security-group "nsg-$APPGW_SUBNET"
```

**Verificar la salud del backend** (DVWA debe verse *Healthy*):

```bash
az network application-gateway show-backend-health \
  -g $RG -n $APPGW --query "backendAddressPools[].backendHttpSettingsCollection[].servers[].health" -o tsv
```

> Si aparece *Unhealthy*, suele ser el sondeo por defecto (espera 200–399 en `/`). DVWA responde **302** hacia `login.php`, que es saludable; si no, crea un *probe* personalizado con `--path /login.php` y `--match-status-codes 200-399`. Confirma también que las reglas del **Zentyal/NSG del Lab 2** permiten el tráfico `10.0.2.0/24 → 10.1.3.0/24:80`.

## A.6 – Probar el bloqueo: SQL Injection y Command Injection

Abre en el navegador **`http://$APPGW_PIP/`** (la DVWA, ahora **detrás del WAF**). Inicia sesión (`admin` / `password`) y confirma **DVWA Security = low**. Repite **los mismos ataques de la Sesión 3**:

**1) Command Injection** (módulo *Command Injection* de DVWA). En el campo de IP intenta:
```
127.0.0.1; ls
127.0.0.1 && cat /etc/passwd
```
- **En la Sesión 3 (sin WAF):** el comando se ejecutaba y devolvía la salida.
- **Ahora (con WAF en Prevention):** el Application Gateway responde **`403 Forbidden`** (página de bloqueo del WAF). La regla CRS del grupo **REQUEST-932-APPLICATION-ATTACK-RCE** detecta el patrón de inyección de comandos.

**2) SQL Injection** (módulo *SQL Injection* de DVWA). En el campo *User ID* intenta:
```
1' OR '1'='1
1' UNION SELECT user,password FROM users-- -
```
- **Sin WAF:** devolvía filas / credenciales.
- **Con WAF:** **`403 Forbidden`**. Lo bloquea el grupo **REQUEST-942-APPLICATION-ATTACK-SQLI**.

**Evidencia en los logs del WAF** (opcional, si activaste diagnósticos): cada bloqueo genera un evento `ruleId`, `action: Blocked`, y el `Message` de la regla CRS. También puedes contrastar **Detection vs Prevention** cambiando el modo de la política (A.3) y repitiendo.

> **Conclusión de la Parte A:** el WAF es un **control compensatorio** en el borde — protege incluso a una aplicación vulnerable como DVWA. No sustituye corregir el código (eso lo ataca la Parte B), pero **reduce el riesgo** de inmediato. Es *defensa en profundidad*.

---

# PARTE B – Pipeline de CI/CD con GitHub Actions hacia App Service

Ahora atacamos el problema **en el código y el pipeline**: un workflow de GitHub Actions que **analiza** la aplicación con cinco herramientas y **despliega** a un **Azure App Service**. La autenticación a Azure usa **OIDC** (sin guardar credenciales de larga vida).

```
push → [ SonarCloud ][ Qwiet ][ Snyk ] (SAST/SCA sobre el código)
     → [ Checkov ] (IaC/Dockerfile)  → [ Build imagen ] → [ Trivy ] (imagen)
     → [ Push a ACR ] → [ azure/login OIDC ] → [ webapps-deploy → App Service ]
```

## B.1 – Preparar el repositorio (fork de DVWA)

1. Haz **fork** del código fuente de DVWA a tu cuenta: **https://github.com/digininja/DVWA** → *Fork* → queda en `https://github.com/<usuario>/DVWA`.
2. Clónalo (o edítalo por la web). Añadiremos el workflow y, si no existe, un `Dockerfile` de despliegue.

> DVWA es **PHP**. SonarCloud, Qwiet y Snyk analizarán el **código PHP**; Checkov el **Dockerfile/IaC**; Trivy la **imagen** construida.

## B.2 – Crear el App Service y el registro de contenedores

Reutilizamos el **ACR** de la Sesión 3 y creamos un **App Service for Containers** (Linux) como destino del despliegue.

```bash
# Plan Linux + Web App para contenedor (imagen placeholder inicial)
az appservice plan create -g $RG -n $APP_PLAN --location $LOC --is-linux --sku B1

az webapp create -g $RG -n $WEBAPP --plan $APP_PLAN \
  --deployment-container-image-name "mcr.microsoft.com/appsvc/staticsite:latest"

# Permitir que el App Service lea del ACR (managed identity + AcrPull)
az webapp identity assign -g $RG -n $WEBAPP
export APP_MI=$(az webapp identity show -g $RG -n $WEBAPP --query principalId -o tsv)
export ACR_ID=$(az acr show -n $ACR --query id -o tsv)
az role assignment create --assignee-object-id $APP_MI --assignee-principal-type ServicePrincipal \
  --role AcrPull --scope $ACR_ID

# Endurecimiento básico
az webapp update -g $RG -n $WEBAPP --set httpsOnly=true
echo "App Service: https://$WEBAPP.azurewebsites.net"
```

## B.3 – Autenticación sin secretos: OIDC (federated credential)

Creamos una **identidad de aplicación** en Entra ID y una **credencial federada** que confía en tu repositorio de GitHub. El workflow obtendrá un **token OIDC** por ejecución — **sin secretos de larga vida**.

```bash
# 1. Registrar la aplicación (service principal)
export APP_ID=$(az ad app create --display-name "gha-oidc-dvwa-$INI" --query appId -o tsv)
az ad sp create --id $APP_ID
export SP_OID=$(az ad sp show --id $APP_ID --query id -o tsv)

# 2. Permisos para desplegar y publicar imágenes (mínimo: sobre el RG y el ACR)
az role assignment create --assignee $APP_ID --role "Contributor" \
  --scope "/subscriptions/$SUB_ID/resourceGroups/$RG"
az role assignment create --assignee $APP_ID --role "AcrPush" --scope $ACR_ID

# 3. Credencial federada: confía en la rama main de tu repo
az ad app federated-credential create --id $APP_ID --parameters '{
  "name": "github-main",
  "issuer": "https://token.actions.githubusercontent.com",
  "subject": "repo:'"$GH"'/DVWA:ref:refs/heads/main",
  "audiences": ["api://AzureADTokenExchange"]
}'

echo "AZURE_CLIENT_ID=$APP_ID"
echo "AZURE_TENANT_ID=$TENANT_ID"
echo "AZURE_SUBSCRIPTION_ID=$SUB_ID"
```

## B.4 – Cargar los secretos en GitHub

En tu repo `DVWA` → **Settings → Secrets and variables → Actions → New repository secret**, crea:

| Secreto | Valor / origen |
|---|---|
| `AZURE_CLIENT_ID` | `APP_ID` del paso B.3 |
| `AZURE_TENANT_ID` | tu Tenant ID |
| `AZURE_SUBSCRIPTION_ID` | tu Subscription ID |
| `ACR_LOGIN_SERVER` | `acrlab3<ini>.azurecr.io` |
| `ACR_USERNAME` | usuario admin del ACR (`az acr credential show`) |
| `ACR_PASSWORD` | password admin del ACR |
| `SONAR_TOKEN` | token de **SonarCloud** (My Account → Security → Generate Token) |
| `SNYK_TOKEN` | token de **Snyk** (Account settings → API Token) |
| `SHIFTLEFT_ACCESS_TOKEN` | token CI de **Qwiet** (Qwiet → Account → CI token) |

> Además, crea en **SonarCloud** la organización y el proyecto (o usa *Analyze new project*), y anota el **project key** y la **organization** para el archivo `sonar-project.properties`.

Crea en la raíz del repo **`sonar-project.properties`**:
```
sonar.organization=<tu-organizacion-sonarcloud>
sonar.projectKey=<usuario>_DVWA
sonar.sources=.
sonar.sourceEncoding=UTF-8
```

Si el repo no trae un `Dockerfile` de despliegue autocontenido, crea uno (DVWA + Apache/PHP; para el laboratorio puedes partir de la imagen ya usada en la Sesión 3):
```dockerfile
# Dockerfile (despliegue) — imagen DVWA autocontenida usada en la Sesión 3
FROM ghcr.io/digininja/dvwa:latest
EXPOSE 80
```
> DVWA necesita base de datos. La imagen de la Sesión 3 (`web-dvwa`) la trae **incorporada**; si usas la imagen oficial `digininja/dvwa`, en producción conectarías una **Azure Database for MySQL** (fuera del alcance de este lab). Para el ejercicio de pipeline basta con desplegar la imagen autocontenida.

## B.5 – El workflow completo (5 escáneres + build + deploy)

Crea **`.github/workflows/devsecops.yml`**:

```yaml
name: DevSecOps CI/CD

on:
  push:
    branches: [ main ]
  workflow_dispatch:

permissions:
  contents: read
  id-token: write          # necesario para OIDC (azure/login)

jobs:
  # ---------- 1. SAST / SCA sobre el código ----------
  sast-sca:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0     # SonarCloud necesita el historial completo

      - name: SonarCloud (SAST)
        uses: SonarSource/sonarqube-scan-action@v5
        env:
          SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}
          SONAR_HOST_URL: https://sonarcloud.io

      - name: Snyk (SCA/SAST)
        uses: snyk/actions/php@master
        continue-on-error: true      # gate informativo; pon 'false' para bloquear
        env:
          SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
        with:
          command: test

      - name: Qwiet preZero (SAST)
        continue-on-error: true
        env:
          SHIFTLEFT_ACCESS_TOKEN: ${{ secrets.SHIFTLEFT_ACCESS_TOKEN }}
        run: |
          curl -s https://cdn.shiftleft.io/download/sl > sl && chmod +x sl
          ./sl analyze --app DVWA-${{ github.actor }} --tag branch=main --php .

  # ---------- 2. IaC / Dockerfile ----------
  iac-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Checkov (IaC + Dockerfile)
        uses: bridgecrewio/checkov-action@v12
        with:
          directory: .
          framework: dockerfile,secrets
          soft_fail: true            # informativo; quítalo para que sea gate estricto

  # ---------- 3. Build + escaneo de imagen + push ----------
  build-scan-push:
    needs: [ sast-sca, iac-scan ]
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Login al ACR
        uses: docker/login-action@v3
        with:
          registry: ${{ secrets.ACR_LOGIN_SERVER }}
          username: ${{ secrets.ACR_USERNAME }}
          password: ${{ secrets.ACR_PASSWORD }}

      - name: Construir la imagen
        run: docker build -t ${{ secrets.ACR_LOGIN_SERVER }}/dvwa:${{ github.sha }} .

      - name: Trivy (escaneo de la imagen)
        uses: aquasecurity/trivy-action@0.28.0
        with:
          image-ref: ${{ secrets.ACR_LOGIN_SERVER }}/dvwa:${{ github.sha }}
          severity: CRITICAL,HIGH
          exit-code: '0'             # informativo; '1' para bloquear con CRITICAL/HIGH

      - name: Publicar la imagen en el ACR
        run: docker push ${{ secrets.ACR_LOGIN_SERVER }}/dvwa:${{ github.sha }}

  # ---------- 4. Deploy a Azure App Service (OIDC) ----------
  deploy:
    needs: build-scan-push
    runs-on: ubuntu-latest
    environment: production          # gate opcional: revisor requerido
    steps:
      - name: Login a Azure con OIDC
        uses: azure/login@v2
        with:
          client-id: ${{ secrets.AZURE_CLIENT_ID }}
          tenant-id: ${{ secrets.AZURE_TENANT_ID }}
          subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}

      - name: Desplegar la imagen al App Service
        uses: azure/webapps-deploy@v3
        with:
          app-name: app-dvwa-<INICIALES>       # reemplaza por tu WEBAPP
          images: ${{ secrets.ACR_LOGIN_SERVER }}/dvwa:${{ github.sha }}
```

**Notas de diseño del workflow:**
- **Cinco escáneres presentes:** SonarCloud + Snyk + Qwiet (SAST/SCA del código), Checkov (IaC/Dockerfile) y Trivy (imagen).
- Los escáneres empiezan como **informativos** (`continue-on-error`, `soft_fail`, `exit-code: '0'`). Para convertirlos en **gates estrictos** que **detengan** el pipeline ante hallazgos, cambia esos valores (`false` / quitar `soft_fail` / `exit-code: '1'`). Es el *quality gate* de la Sesión 3 aplicado a CI/CD.
- **Sin secretos de larga vida hacia Azure:** `azure/login@v2` usa **OIDC** (`id-token: write`).
- El job `deploy` usa un **environment `production`**; si le añades **revisor requerido** (Settings → Environments), tendrás **entrega continua** (aprobación manual) como en la teoría.

## B.6 – Ejecutar y revisar los gates

1. Haz **commit** de `sonar-project.properties`, el `Dockerfile` y `.github/workflows/devsecops.yml`.
2. Ve a **Actions** → observa la ejecución. Revisa cada job:
   - **sast-sca:** resultados de SonarCloud (en sonarcloud.io), Snyk y Qwiet.
   - **iac-scan:** hallazgos de Checkov sobre el Dockerfile.
   - **build-scan-push:** el reporte de Trivy sobre la imagen y el push al ACR.
   - **deploy:** el despliegue al App Service (aprueba si configuraste el revisor).
3. Abre **`https://app-dvwa-<iniciales>.azurewebsites.net`** para ver DVWA desplegada por el pipeline.
4. **Endurece un gate:** pon `exit-code: '1'` en Trivy y vuelve a ejecutar; el pipeline **falla** si hay vulnerabilidades CRITICAL/HIGH — y por tanto **no despliega**. Ese es DevSecOps en acción.

## B.7 – (Opcional) Proteger el App Service con el WAF

Puedes cerrar el círculo apuntando el **backend del Application Gateway** (Parte A) al **App Service** en lugar de al ACI, de modo que la app desplegada por el pipeline también quede **detrás del WAF**:

```bash
# Cambiar el backend pool del App Gateway al FQDN del App Service
az network application-gateway address-pool update \
  -g $RG --gateway-name $APPGW -n appGatewayBackendPool \
  --servers "$WEBAPP.azurewebsites.net"
# Ajustar la HTTP setting para usar el host del backend (App Service exige SNI/host)
az network application-gateway http-settings update \
  -g $RG --gateway-name $APPGW -n appGatewayBackendHttpSettings \
  --host-name-from-backend-pool true
```

> Así, **pipeline (Parte B) + WAF (Parte A)** trabajan juntos: el código se analiza y despliega automáticamente, y el borde queda protegido. Es la combinación *shift-left* + *defensa en el borde*.

---

## Limpieza

```bash
# Parte A – WAF y App Gateway
az network application-gateway delete -g $RG -n $APPGW
az network public-ip delete -g $RG -n "${APPGW}-pip"
az network application-gateway waf-policy delete -g $RG -n $WAF_POLICY
az network vnet subnet update -g $RG --vnet-name $HUB -n $APPGW_SUBNET --network-security-group "" 2>/dev/null
az network nsg delete -g $RG -n "nsg-$APPGW_SUBNET"
az network vnet subnet delete -g $RG --vnet-name $HUB -n $APPGW_SUBNET

# Parte B – App Service y OIDC
az webapp delete -g $RG -n $WEBAPP
az appservice plan delete -g $RG -n $APP_PLAN --yes
az ad app delete --id $APP_ID

# La DVWA (ACI) y el ACR son de la Sesión 3: bórralos solo si ya no los necesitas.
```

> No borres los recursos base del **Laboratorio 2** (Zentyal, VNets, peering) salvo que ya no los necesites.

---

## Checklist de finalización

**Parte A – WAF**
- [ ] Subred `AppGwSubnet` (10.0.2.0/24) e IP pública creadas.
- [ ] Política WAF con **OWASP CRS 3.2** en modo **Prevention**.
- [ ] Application Gateway **WAF_v2** con backend = IP privada de DVWA y política asociada.
- [ ] NSG del App Gateway (GatewayManager 65200-65535 + HTTP 80) y backend **Healthy**.
- [ ] **Command Injection** bloqueado (403) a través del WAF.
- [ ] **SQL Injection** bloqueado (403) a través del WAF.
- [ ] *(Opcional)* Contraste **Detection vs Prevention** observado en logs.

**Parte B – Pipeline**
- [ ] Fork de DVWA; `sonar-project.properties`, `Dockerfile` y workflow creados.
- [ ] App Service (contenedor) + AcrPull por managed identity.
- [ ] **OIDC** (app + credencial federada) configurado; secretos en GitHub cargados.
- [ ] Workflow ejecutado con **SonarCloud, Qwiet, Snyk, Checkov y Trivy** visibles en el pipeline.
- [ ] Despliegue a **App Service** por OIDC exitoso.
- [ ] Un gate endurecido (`exit-code: '1'` en Trivy) detiene el pipeline ante CRITICAL/HIGH.
- [ ] *(Opcional)* App Service protegido por el WAF (B.7).

---

## Solución de problemas frecuentes

| Síntoma | Causa probable | Solución |
|---|---|---|
| Backend *Unhealthy* en el App Gateway | Sondeo por defecto o NSG/Zentyal | Probe a `/login.php` con `--match-status-codes 200-399`; permitir `10.0.2.0/24 → 10.1.3.0/24:80` en el Lab 2 |
| El WAF bloquea también el login de DVWA | Falsos positivos del CRS | Empezar en **Detection**, o deshabilitar reglas puntuales con `waf-policy managed-rule rule-set` tras identificar el `ruleId` |
| Los ataques NO se bloquean | Política en Detection o no asociada | Confirmar `--mode Prevention` y que el App Gateway tiene `--waf-policy` asociada |
| `azure/login` falla (OIDC) | `subject` de la credencial federada no coincide | Debe ser `repo:<usuario>/DVWA:ref:refs/heads/main` y el workflow tener `id-token: write` |
| El App Service no arranca la imagen | Falta AcrPull o DVWA sin BD | Verificar el rol AcrPull de la managed identity; usar la imagen autocontenida (BD incluida) |
| SonarCloud no analiza | Falta org/projectKey o `fetch-depth: 0` | Completar `sonar-project.properties` y el checkout con historial completo |
| Qwiet `sl analyze` falla | Token ausente o lenguaje incorrecto | Definir `SHIFTLEFT_ACCESS_TOKEN` y usar `--php` (DVWA es PHP) |

---

## Referencias

- WAF en Application Gateway (CLI): https://learn.microsoft.com/azure/web-application-firewall/ag/tutorial-restrict-web-traffic-cli
- Política WAF (CLI): https://learn.microsoft.com/cli/azure/network/application-gateway/waf-policy
- Grupos y reglas del OWASP CRS: https://learn.microsoft.com/azure/web-application-firewall/ag/application-gateway-crs-rulegroups-rules
- CI/CD de contenedor a App Service con GitHub Actions: https://learn.microsoft.com/azure/app-service/deploy-container-github-action
- Azure Login (OIDC): https://github.com/Azure/login · webapps-deploy: https://github.com/Azure/webapps-deploy
- SonarQube Scan Action (SonarCloud): https://github.com/SonarSource/sonarqube-scan-action
- Snyk Actions: https://github.com/snyk/actions · Trivy Action: https://github.com/aquasecurity/trivy-action · Checkov Action: https://github.com/bridgecrewio/checkov-action
- Qwiet AI en GitHub Actions: https://docs.shiftleft.io/sast/workflows/github
- DVWA: https://github.com/digininja/DVWA
