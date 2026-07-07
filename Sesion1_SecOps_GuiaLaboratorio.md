# Guía de Laboratorio — Sesión 1
**Curso SecOps · Fundamentos de Seguridad en la Nube**
Docente: Manuel Alejandro Vargas Rojas — manuelvargasrojas@cedoc.edu.co
Duración: 90 minutos + actividad final de threat modeling

---

## Objetivos del laboratorio

Al finalizar, el estudiante habrá:

1. Creado identidades (usuarios y grupos) en Microsoft Entra ID y asignado roles RBAC con alcance de grupo de recursos y de recurso específico (un **App Service**).
2. Habilitado la identidad administrada (managed identity) del App Service y consumido un secreto de Key Vault mediante **Key Vault references**, **sin credenciales** en la configuración.
3. Asignado una plantilla integrada de Azure Policy y creado + asignado una política personalizada que gobierna el App Service.
4. Evaluado la postura de seguridad (CSPM) con **Microsoft Defender for Cloud** y contrastado los hallazgos con **Prowler**.
5. Modelado las amenazas de la arquitectura del laboratorio con **OWASP Threat Dragon** aplicando STRIDE.

## Prerrequisitos

| Requisito | Detalle |
|---|---|
| Suscripción de Azure | Con rol **Owner** (o al menos *Contributor* + *User Access Administrator*). Sirve la suscripción gratuita o Azure for Students |
| Permisos en Entra ID | Poder crear usuarios y grupos (rol *User Administrator* o superior en el tenant) |
| Azure Cloud Shell (Bash) | Disponible en el portal (icono `>_`). Trae Azure CLI preinstalado |
| Navegador | Edge, Chrome o Firefox actualizado |
| Threat Dragon | Se usa en la Actividad 5: versión web o instalador de escritorio (se indica en la actividad) |

> **Convención de nombres:** en toda la guía reemplaza `<iniciales>` por tus iniciales en minúscula (ej. `mavr`). Azure exige nombres globalmente únicos para App Service y Key Vault.

## Arquitectura que construirás

```
Suscripción
└── rg-secops-<iniciales>               (grupo de recursos del lab)
    ├── plan-secops-<iniciales>         (App Service Plan, Linux B1)
    ├── app-secops-<iniciales>          (Web App con managed identity)
    └── kv-secops-<iniciales>           (Key Vault con un secreto)

Entra ID
├── Usuario: ana.ops@<tenant>           (operadora)
├── Usuario: luis.dev@<tenant>          (desarrollador)
└── Grupo:  grp-secops-operaciones      (contiene a ana.ops)
```

Distribución sugerida del tiempo: preparación 5 min · Actividad 1: 20 min · Actividad 2: 20 min · Actividad 3: 15 min · Actividad 4: 20 min · cierre y limpieza 10 min. La Actividad 5 (Threat Dragon) puede hacerse en clase si el tiempo alcanza o como trabajo autónomo entregable.

---

## Actividad 0 — Preparación (5 min)

1. Ingresa a [https://portal.azure.com](https://portal.azure.com) y abre **Cloud Shell** (icono `>_` en la barra superior). Selecciona **Bash**. Si es la primera vez, acepta la creación del almacenamiento de respaldo.
2. Define variables de trabajo y crea el grupo de recursos:

```bash
# Ajusta tus iniciales y la región
INI="<iniciales>"
LOC="eastus"
RG="rg-secops-$INI"
APP="app-secops-$INI"
PLAN="plan-secops-$INI"
KV="kv-secops-$INI"

az group create --name $RG --location $LOC --tags entorno=laboratorio curso=secops
```

3. Verifica: `az group show --name $RG --output table`

> **Conexión con la teoría:** al usar App Service (PaaS), Microsoft opera el SO y el runtime; a ti te quedan el código, la configuración, las identidades y los datos. Este laboratorio trabaja exactamente sobre esa porción del modelo de responsabilidad compartida.

---

## Actividad 1 — Identidades, roles y perfiles con RBAC (20 min)

**Meta:** crear dos usuarios y un grupo, desplegar el App Service, y demostrar el principio de menor privilegio asignando roles distintos a alcances distintos: uno a nivel de **grupo de recursos** y otro a nivel de **recurso específico** (el App Service).

### 1.1 Crear usuarios en Microsoft Entra ID (portal)

1. Portal → busca **Microsoft Entra ID** → **Users** → **New user** → **Create new user**.
2. Crea el primer usuario:
   - *User principal name:* `ana.ops` (el dominio del tenant se completa solo)
   - *Display name:* `Ana Operaciones`
   - Marca **Auto-generate password** y **copia la contraseña** (la necesitarás en 1.5).
3. Repite para el segundo usuario: `luis.dev` / `Luis Desarrollador`.

Equivalente en CLI (opcional):

```bash
DOMAIN=$(az rest --method get --url 'https://graph.microsoft.com/v1.0/domains' --query "value[?isDefault].id" -o tsv)

az ad user create --display-name "Ana Operaciones" \
  --user-principal-name "ana.ops@$DOMAIN" \
  --password "P@ssw0rdLab2026!" --force-change-password-next-sign-in true

az ad user create --display-name "Luis Desarrollador" \
  --user-principal-name "luis.dev@$DOMAIN" \
  --password "P@ssw0rdLab2026!" --force-change-password-next-sign-in true
```

### 1.2 Crear un grupo y agregar miembros

1. **Microsoft Entra ID** → **Groups** → **New group**.
   - *Group type:* Security · *Group name:* `grp-secops-operaciones`
   - *Members:* agrega a **Ana Operaciones**.
2. Crea el grupo y verifica que Ana aparece como miembro.

```bash
# Equivalente CLI
az ad group create --display-name "grp-secops-operaciones" --mail-nickname "grpsecopsops"
ANA_ID=$(az ad user list --filter "startswith(userPrincipalName,'ana.ops')" --query "[0].id" -o tsv)
az ad group member add --group "grp-secops-operaciones" --member-id $ANA_ID
```

### 1.3 Desplegar el App Service

Crea el plan y la aplicación web que serán el "recurso específico" del laboratorio:

```bash
az appservice plan create --name $PLAN --resource-group $RG --location $LOC \
  --is-linux --sku B1

az webapp create --name $APP --resource-group $RG --plan $PLAN \
  --runtime "PYTHON:3.12" --tags costCenter=SecOps101
```

Verifica que responde: abre `https://app-secops-<iniciales>.azurewebsites.net` (verás la página de bienvenida por defecto).

> El SKU B1 tiene costo bajo por hora (se borra al final). Si tu suscripción lo permite, puedes usar `--sku F1` (gratuito), pero la consola SSH de la Actividad 2.4 no está disponible en F1.

### 1.4 Asignar roles con alcances diferentes

**Asignación A — rol al GRUPO sobre el grupo de recursos (perfil de operaciones):**

1. Portal → **Resource groups** → `rg-secops-<iniciales>` → **Access control (IAM)**.
2. **Add** → **Add role assignment**.
3. Pestaña **Role** → selecciona **Reader**.
4. Pestaña **Members** → *User, group, or service principal* → **Select members** → busca `grp-secops-operaciones`.
5. **Review + assign**. Si aparece la pestaña *Assignment type*, elige **Active / Permanent** (la opción *Eligible* es PIM, se menciona al final).

**Asignación B — rol al USUARIO sobre el recurso específico (perfil de desarrollador):**

1. Portal → ve directamente al App Service `app-secops-<iniciales>` → **Access control (IAM)**.
2. **Add role assignment** → rol **Website Contributor** → miembro `Luis Desarrollador` → **Review + assign**.

> *Website Contributor* permite administrar la web app (desplegar código, reiniciar, cambiar configuración) pero **no** administrar el plan, ni asignar roles, ni tocar el Key Vault. Ese es el perfil de un desarrollador de la aplicación.

Equivalente en CLI:

```bash
GRP_ID=$(az ad group show --group "grp-secops-operaciones" --query id -o tsv)
LUIS_ID=$(az ad user list --filter "startswith(userPrincipalName,'luis.dev')" --query "[0].id" -o tsv)
APP_ID=$(az webapp show --name $APP --resource-group $RG --query id -o tsv)

# A: grupo -> Reader sobre el grupo de recursos
az role assignment create --assignee-object-id $GRP_ID --assignee-principal-type Group \
  --role "Reader" --scope $(az group show --name $RG --query id -o tsv)

# B: usuario -> Website Contributor sobre el App Service (recurso específico)
az role assignment create --assignee-object-id $LUIS_ID --assignee-principal-type User \
  --role "Website Contributor" --scope $APP_ID
```

### 1.5 Validar el menor privilegio

1. Abre una **ventana de incógnito**, entra a portal.azure.com con `ana.ops@<tenant>` (cambia la contraseña cuando lo pida).
2. Comprueba que Ana **ve** el App Service y el resto del grupo de recursos, pero los botones **Stop/Restart/Delete** están deshabilitados (Reader).
3. Repite con `luis.dev`: Luis **puede** reiniciar la web app (pruébalo: botón **Restart**), pero **no ve** nada fuera de ese recurso y no puede entrar al Key Vault.

**Preguntas de verificación:**
- ¿Por qué asignamos el rol al *grupo* y no directamente a Ana? ¿Qué pasa cuando entra una segunda persona a operaciones?
- ¿Qué diferencia hay entre el alcance de la Asignación A y el de la B? ¿Cuál respeta mejor el menor privilegio para el caso de Luis?
- Luis administra la aplicación pero no puede leer los secretos que ella usa (lo verás en la Actividad 2). ¿Por qué es esa separación tan valiosa?

> **Nota (JIT/JEA):** con licencia Entra ID P2, la pestaña *Assignment type* permite asignaciones **Eligible** (PIM): el rol se activa solo cuando se necesita. Es la materialización de Just-In-Time vista en Zero Trust.

---

## Actividad 2 — Identidad administrada del App Service + Key Vault references (20 min)

**Meta:** que la aplicación consuma un secreto de Key Vault **sin ninguna credencial** en su configuración ni en su código, usando la identidad administrada asignada por el sistema y las *Key Vault references*.

### 2.1 Crear el Key Vault y el secreto

```bash
# Key Vault con autorización RBAC (modelo recomendado)
az keyvault create --name $KV --resource-group $RG --location $LOC --enable-rbac-authorization true

# Para poder crear el secreto, date a ti mismo el rol de oficial de secretos
MY_ID=$(az ad signed-in-user show --query id -o tsv)
KV_ID=$(az keyvault show --name $KV --query id -o tsv)
az role assignment create --assignee-object-id $MY_ID --assignee-principal-type User \
  --role "Key Vault Secrets Officer" --scope $KV_ID

# Espera ~1 minuto a que propague el rol y crea el secreto
az keyvault secret set --vault-name $KV --name "cadena-conexion" \
  --value "Server=db1;User=app;Pwd=SuperSecreta123"
```

### 2.2 Habilitar la identidad administrada del App Service

```bash
az webapp identity assign --name $APP --resource-group $RG
```

En el portal puedes verla en: App Service → **Settings** → **Identity** → pestaña *System assigned* → estado **On**. Copia el *Object (principal) ID*: esa es la identidad de tu aplicación en Entra ID — nadie conoce su "contraseña", la administra Azure.

### 2.3 Autorizar la identidad de la app en el Key Vault

```bash
APP_MI=$(az webapp identity show --name $APP --resource-group $RG --query principalId -o tsv)

az role assignment create --assignee-object-id $APP_MI --assignee-principal-type ServicePrincipal \
  --role "Key Vault Secrets User" --scope $KV_ID
```

En portal sería: Key Vault → **Access control (IAM)** → **Add role assignment** → rol *Key Vault Secrets User* → **Members**: *Managed identity* → *App Service* → tu app.

Observa el detalle: la app recibe **solo lectura de secretos** (Secrets User), no administración del vault. Menor privilegio también para las aplicaciones. Y Luis (*Website Contributor*) puede administrar la app, pero **no** tiene ningún rol en el Key Vault: administrar la aplicación ≠ conocer sus secretos.

### 2.4 Consumir el secreto con una Key Vault reference

Crea un app setting cuyo valor es una **referencia** al secreto (no el secreto):

```bash
SECRET_URI=$(az keyvault secret show --vault-name $KV --name "cadena-conexion" --query id -o tsv)

az webapp config appsettings set --name $APP --resource-group $RG \
  --settings CADENA_CONEXION="@Microsoft.KeyVault(SecretUri=$SECRET_URI)"
```

**Verifica la resolución (portal):**

1. App Service → **Settings** → **Environment variables**.
2. La variable `CADENA_CONEXION` aparece con el ícono de Key Vault y estado **Resolved** (marca verde). Si haces clic en editar, verás la referencia `@Microsoft.KeyVault(...)`, **nunca** el valor.

**Verifica desde dentro de la app (SSH, requiere SKU B1):**

1. App Service → **Development Tools** → **SSH** → **Go**.
2. En la consola: `env | grep CADENA`
3. Verás el **valor real** del secreto: la plataforma lo resolvió e inyectó como variable de entorno usando la managed identity. La aplicación lo consume como cualquier variable, sin saber siquiera que existe un Key Vault.

**Preguntas de verificación:**
- ¿En qué parte del ejercicio se escribió una credencial en la configuración de la app? (Respuesta esperada: en ninguna — solo una referencia.)
- ¿Qué categorías STRIDE mitiga esto principalmente? (Spoofing / Information Disclosure por credenciales filtradas en código o configuración.)
- Si rotas el secreto en Key Vault, ¿qué debes cambiar en el App Service? (Nada: la referencia apunta al secreto; App Service re-resuelve el valor periódicamente o al reiniciar.)
- ¿Qué pasaría si borras la app? (La identidad del sistema muere con el recurso: no quedan credenciales huérfanas.)

---

## Actividad 3 — Azure Policy: plantilla integrada + política personalizada (15 min)

**Meta:** gobernar la configuración con dos políticas: una **integrada** (plantilla) que exige etiquetas y una **personalizada** que impide App Services sin HTTPS obligatorio.

### 3.1 Asignar una plantilla integrada (portal)

1. Portal → busca **Policy** → **Authoring** → **Assignments** → **Assign policy**.
2. *Scope:* selecciona tu suscripción y el grupo de recursos `rg-secops-<iniciales>`.
3. *Policy definition:* busca **"Require a tag on resources"** y selecciónala.
4. En **Parameters**, *Tag Name:* `costCenter`.
5. Deja el resto por defecto → **Review + create** → **Create**.

> Esta definición integrada tiene efecto `deny`: bloqueará la creación de recursos sin la etiqueta. La evaluación de recursos *existentes* puede tardar 15–30 min en reflejarse en Compliance. (Tu App Service ya la cumple: lo creaste con `costCenter=SecOps101` en la Actividad 1.)

**Prueba la política (espera ~5-10 min tras la asignación):**

```bash
# Debe FALLAR (sin etiqueta costCenter)
az storage account create --name "stpolicy$INI" --resource-group $RG --location $LOC --sku Standard_LRS

# Debe FUNCIONAR
az storage account create --name "stpolicy$INI" --resource-group $RG --location $LOC \
  --sku Standard_LRS --tags costCenter=SecOps101
```

### 3.2 Crear y asignar una política personalizada para App Service

Crearemos una política que **deniega aplicaciones App Service que no fuercen HTTPS** (la propiedad `httpsOnly` nace en `false` por defecto: un clásico de A05 Security Misconfiguration).

1. Portal → **Policy** → **Authoring** → **Definitions** → **+ Policy definition**.
2. *Definition location:* tu suscripción · *Name:* `Denegar App Service sin HTTPS - SecOps`
3. *Category:* Create new → `SecOps-Lab`
4. En **Policy rule** pega:

```json
{
  "mode": "All",
  "policyRule": {
    "if": {
      "allOf": [
        {
          "field": "type",
          "equals": "Microsoft.Web/sites"
        },
        {
          "field": "Microsoft.Web/sites/httpsOnly",
          "notEquals": "true"
        }
      ]
    },
    "then": {
      "effect": "[parameters('effectType')]"
    }
  },
  "parameters": {
    "effectType": {
      "type": "String",
      "defaultValue": "Deny",
      "allowedValues": [ "Deny", "Disabled" ],
      "metadata": {
        "displayName": "Efecto",
        "description": "Habilita o deshabilita la ejecución de la política"
      }
    }
  }
}
```

5. **Save**. Luego, desde la misma definición → **Assign** → *Scope:* `rg-secops-<iniciales>` → **Create**.

**Prueba la política personalizada (espera ~5-10 min):**

```bash
# Debe FALLAR: una web app nueva sin HTTPS obligatorio (httpsOnly=false por defecto)
az webapp create --name "app-inseguro-$INI" --resource-group $RG --plan $PLAN \
  --runtime "PYTHON:3.12" --tags costCenter=SecOps101

# Debe FUNCIONAR: la misma app forzando HTTPS desde el nacimiento
az webapp create --name "app-inseguro-$INI" --resource-group $RG --plan $PLAN \
  --runtime "PYTHON:3.12" --tags costCenter=SecOps101 --https-only true
```

El error `RequestDisallowedByPolicy` es la política actuando **antes** de que exista el recurso inseguro: gobierno preventivo, no correctivo.

6. Revisa **Policy → Compliance**: tu app original `app-secops-<iniciales>` aparecerá como **no conforme** (fue creada sin `httpsOnly`). **No la corrijas todavía** — será tu remediación guiada en la Actividad 4.

**Preguntas de verificación:**
- ¿Cuál es la diferencia práctica entre los efectos `Audit` y `Deny`? ¿Cuándo usarías cada uno en una organización real?
- ¿Por qué `Deny` no corrigió la app existente? (Deny bloquea peticiones de creación/actualización; lo existente solo queda marcado como no conforme.)
- ¿Por qué la política personalizada usa un parámetro `effectType`? (Pista: troubleshooting sin reescribir la definición.)

---

## Actividad 4 — CSPM: Defender for Cloud + Prowler (20 min)

**Meta:** evaluar la postura de seguridad de la suscripción con la herramienta nativa (Defender for Cloud) y con una herramienta open source multinube (Prowler), y comparar resultados.

### 4.1 Microsoft Defender for Cloud (10 min)

1. Portal → busca **Microsoft Defender for Cloud**.
2. Si es la primera vez, el plan gratuito **Foundational CSPM** se habilita automáticamente al abrirlo (incluye secure score, recomendaciones e inventario; no requiere plan de pago).
3. Ve a **Overview** y observa tu **Secure score**. Anótalo: `______ %`
4. Entra a **Recommendations**. Identifica al menos 3 recomendaciones. Típicas del lab:
   - *App Service apps should only be accessible over HTTPS* (¡tu app de la Actividad 1!)
   - *App Service apps should have remote debugging turned off / FTP deployments disabled*
   - *Storage account should use secure transfer / disable public network access*
5. **Remedia la recomendación de HTTPS** — la misma no conformidad que dejó marcada Azure Policy:

```bash
# Forzar HTTPS en la app original y deshabilitar FTP básico de despliegue
az webapp update --name $APP --resource-group $RG --set httpsOnly=true
az webapp config set --name $APP --resource-group $RG --ftps-state Disabled
```

6. Con esto resolviste a la vez la recomendación de Defender **y** la no conformidad de Policy: dos lentes distintos mirando el mismo riesgo. El secure score tarda en refrescarse (horas); lo importante es el flujo: **medir → priorizar por riesgo → remediar → volver a medir**. Es el ciclo de gestión de riesgos del Bloque 3, automatizado.

### 4.2 Prowler (10 min)

Prowler es una herramienta open source de CSPM que audita Azure (y AWS/GCP/Kubernetes) contra cientos de checks alineados a CIS y otros marcos.

En **Cloud Shell**:

```bash
# 1. Instalar (Cloud Shell trae Python; usa un entorno virtual para evitar conflictos)
python3 -m venv ~/prowler-env
source ~/prowler-env/bin/activate
pip install prowler

# 2. Ejecutar el escaneo usando tus credenciales de Azure CLI ya activas
SUB_ID=$(az account show --query id -o tsv)
prowler azure --az-cli-auth --subscription-ids $SUB_ID

# 3. Al terminar, los reportes quedan en ./output (CSV, JSON y HTML)
ls output/
```

Para ver el reporte HTML: descárgalo desde Cloud Shell (**Manage files → Download**, escribe la ruta `output/<archivo>.html`) y ábrelo en tu navegador. Busca los checks de la categoría `appservice` — ¿detectó Prowler el HTTPS y el FTP de tu app?

**Análisis comparativo (completa la tabla):**

| Criterio | Defender for Cloud | Prowler |
|---|---|---|
| ¿Quién lo mantiene? | | |
| ¿Cubre múltiples nubes? | | |
| Un hallazgo que ambos reportaron | | |
| Un hallazgo que solo reportó uno | | |
| ¿Cómo prioriza (score/severidad)? | | |

**Preguntas de verificación:**
- ¿Por qué una organización usaría ambas herramientas y no solo una?
- Los hallazgos de mala configuración corresponden a la categoría **A05 Security Misconfiguration** del OWASP Top 10 vista en clase — ¿cuáles de tus hallazgos encajan ahí?

> **Nota de permisos:** para un escaneo completo, la identidad usada por Prowler necesita el rol `Reader` sobre la suscripción y permisos de lectura en Microsoft Graph. Con `--az-cli-auth` y tu usuario Owner del lab es suficiente.

---

## Actividad 5 — Threat modeling con OWASP Threat Dragon (en clase o autónoma)

**Meta:** cerrar el ciclo modelando las amenazas de la arquitectura que acabas de construir, con la metodología OWASP vista en el Bloque 6.

### 5.1 Instalar / abrir Threat Dragon

Opciones (elige una):

- **Escritorio (recomendada):** descarga el instalador para tu sistema desde [github.com/OWASP/threat-dragon/releases](https://github.com/OWASP/threat-dragon/releases) (versión 2.x).
- **Web:** usa la demo en línea enlazada desde [owasp.org/www-project-threat-dragon](https://owasp.org/www-project-threat-dragon/) (permite trabajar con modelos locales sin cuenta).

### 5.2 Crear el modelo

1. **Create a new, empty threat model** → *Title:* `Lab SecOps Sesión 1` → *Owner:* tu nombre.
2. En la descripción escribe el alcance: "Web app en App Service con managed identity que lee un secreto de Key Vault vía Key Vault reference; administración vía Azure Portal/CLI; usuarios con RBAC diferenciado".
3. Crea un diagrama nuevo de tipo **STRIDE**.

### 5.3 Dibujar el DFD del laboratorio

Usa los elementos de la paleta:

| Elemento Threat Dragon | Representa |
|---|---|
| Actor | Usuario web anónimo · Tú (administrador) · Ana (Reader) · Luis (Website Contributor) |
| Process | Web app `app-secops` · Azure Portal/ARM (plano de control) |
| Store | Key Vault `kv-secops` |
| Data flow | Usuario web→App (HTTPS) · Admin→Portal (HTTPS) · Luis→App (despliegue) · App→Key Vault (token de MI) |
| Trust boundary | Internet ↔ Azure · plano de control (ARM) ↔ plano de datos (app y vault) |

Dibuja como mínimo: 3 actores, la web app, el Key Vault, los flujos entre ellos y **dos trust boundaries**.

### 5.4 Identificar y documentar amenazas

Para cada elemento, clic derecho (o botón *New Threat*) y registra la amenaza con su categoría STRIDE, severidad y mitigación. Documenta **mínimo 6 amenazas (una por letra de STRIDE)**. Ejemplos de arranque:

| Elemento | Amenaza | STRIDE | Mitigación (¡ya la implementaste!) |
|---|---|---|---|
| Flujo Admin→Portal | Robo de credenciales del administrador | S | MFA / acceso condicional |
| Key Vault | Lectura no autorizada del secreto | I | RBAC *Secrets User* solo para la MI de la app; Luis no tiene rol en el vault |
| Flujo Usuario→App | Tráfico HTTP interceptable | T | `httpsOnly=true` (remediado en Act. 4) + política Deny |
| Flujo Luis→App | Despliegue por FTP sin cifrar | T/S | `ftps-state Disabled` (Act. 4) |
| ARM / suscripción | Cambios sin control por permisos excesivos | E | Roles con alcance mínimo (Act. 1) |
| App / logs | Usuario niega acciones y no hay rastro | R | (Propón tú la mitigación) |
| Web app | Saturación del servicio | D | (Propón tú la mitigación) |

3. Marca cada amenaza como **Mitigated** u **Open** según lo que realmente hiciste en el lab.
4. Genera el reporte: **Report** → imprime/exporta a PDF.

### 5.5 Entregable

Sube al aula virtual un único PDF con:

1. El reporte de Threat Dragon (diagrama + amenazas).
2. Captura del secure score y 3 recomendaciones de Defender for Cloud.
3. Captura de un hallazgo de Prowler.
4. Un párrafo (máx. 10 líneas) respondiendo: *¿qué amenaza de tu modelo NO está mitigada aún y qué control de los vistos en la sesión aplicarías?*

---

## Limpieza de recursos (¡importante!)

Para no consumir crédito (el plan B1 factura por hora):

```bash
# Borra todo el grupo de recursos del laboratorio (incluye plan, apps y vault)
az group delete --name $RG --yes --no-wait

# Borra las asignaciones y definiciones de Policy del lab (portal: Policy → Assignments / Definitions)
# Borra los usuarios y el grupo de prueba
az ad user delete --id "ana.ops@$DOMAIN"
az ad user delete --id "luis.dev@$DOMAIN"
az ad group delete --group "grp-secops-operaciones"
```

Verifica en el portal que `rg-secops-<iniciales>` está en estado *Deleting* y que las asignaciones de Policy del lab fueron eliminadas.

---

## Solución de problemas frecuentes

| Síntoma | Causa probable | Solución |
|---|---|---|
| `AuthorizationFailed` al crear el secreto | El rol *Key Vault Secrets Officer* aún no propaga | Espera 1–2 min y reintenta |
| La Key Vault reference muestra ícono rojo (no resuelta) | Falta el rol *Key Vault Secrets User* a la MI, o error de sintaxis en la referencia | Verifica IAM del vault y la URI; usa App Service → *Diagnose and solve problems* → *Key Vault Application Settings Diagnostics* |
| `env \| grep CADENA` no muestra el valor | La app no se ha reiniciado tras crear el setting | App Service → **Restart** y reintenta la consola SSH |
| La consola SSH no abre | SKU F1 (gratuito) no soporta SSH en Linux | Usa la verificación por portal (estado *Resolved*) o sube el plan a B1 |
| La política no bloquea de inmediato | Las asignaciones tardan ~5–15 min en ser efectivas | Espera y reintenta la creación del recurso |
| Prowler: error de permisos en checks de Entra | Faltan permisos de Microsoft Graph | Aceptable en el lab: analiza los checks que sí corrieron |
| Ana ve otros recursos | El rol se asignó a nivel de suscripción por error | Revisa IAM → Role assignments y corrige el alcance |

## Referencias

- Asignar roles de Azure (portal): https://learn.microsoft.com/azure/role-based-access-control/role-assignments-portal
- Managed identities en App Service: https://learn.microsoft.com/azure/app-service/overview-managed-identity
- Key Vault references en App Service: https://learn.microsoft.com/azure/app-service/app-service-key-vault-references
- Asignar una política integrada: https://learn.microsoft.com/azure/governance/policy/assign-policy-portal
- Crear una definición de política personalizada: https://learn.microsoft.com/azure/governance/policy/tutorials/create-custom-policy-definition
- Secure score en Defender for Cloud: https://learn.microsoft.com/azure/defender-for-cloud/secure-score-security-controls
- Prowler para Azure: https://docs.prowler.com/user-guide/providers/azure/getting-started-azure
- OWASP Threat Dragon: https://owasp.org/www-project-threat-dragon/
