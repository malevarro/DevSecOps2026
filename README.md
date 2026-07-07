# DevSecOps2026

Material de curso de posgrado en **Seguridad en Nubes Públicas / DevSecOps**, orientado a Microsoft Azure. El repositorio reúne guías de laboratorio paso a paso, el listado de herramientas usadas en clase y el material de presentaciones del curso.

**Docente:** Manuel Alejandro Vargas Rojas — `manuelvargasrojas@cedoc.edu.co`

---

## Contenido del repositorio

| Archivo / carpeta | Descripción |
| --- | --- |
| [`Sesion1_SecOps_GuiaLaboratorio.md`](./Sesion1_SecOps_GuiaLaboratorio.md) | Laboratorio 1 — Fundamentos de seguridad en la nube: identidades y RBAC en Microsoft Entra ID, Managed Identity + Key Vault references en App Service, Azure Policy (integrada y personalizada), CSPM con Microsoft Defender for Cloud y Prowler, y threat modeling con OWASP Threat Dragon (STRIDE). |
| [`Sesion2_SecOps_GuiaLaboratorio.md`](./Sesion2_SecOps_GuiaLaboratorio.md) | Laboratorio 2 — Arquitectura de red **Hub & Spoke** en Azure con **Zentyal Server** como NVA/Firewall/IDS-IPS (Suricata), despliegue de una aplicación PaaS de 3 capas (App Service + Function App + Azure SQL con Private Endpoint) sobre esa red, y auditoría CSPM con CloudSploit. |
| [`Sesion3_SecOps_GuiaLaboratorio.md`](./Sesion3_SecOps_GuiaLaboratorio.md) | Laboratorio 3 — Análisis de vulnerabilidades y DevSecOps (SCA, SAST, SAST de IaC, DAST, IAST) con herramientas contenerizadas en **Azure Container Instances** (Trivy, Checkov, SonarQube, OWASP ZAP), acceso remoto a las redes privadas con **Tailscale**, y aplicaciones vulnerables de práctica (`nodejs-goof`, `AzureGoat`). |
| [`Herramientas.md`](./Herramientas.md) | Catálogo de herramientas utilizadas en los laboratorios (Azure, VS Code, Git, Prowler, CloudSploit, Snyk, SonarCloud, Trivy, Mend, Checkov, Tailscale, OWASP ZAP, Zentyal, Qwiet.ai, Microsoft Defender for Cloud, OWASP Threat Dragon), con enlace y logo de cada una. |
| `Images/` | Recursos gráficos (logos de herramientas) usados en `Herramientas.md` y demás guías. |
| `Presentaciones/` | Material de diapositivas de apoyo a las sesiones del curso. |

## Ruta de aprendizaje sugerida

1. **Sesión 1** — Identidad, RBAC, gobierno (Azure Policy) y postura de seguridad (CSPM) sobre un App Service + Key Vault. Cierra con threat modeling STRIDE.
2. **Sesión 2** — Se construye una arquitectura de red segmentada (Hub & Spoke con Zentyal como firewall/IDS-IPS) y se despliega sobre ella la aplicación PaaS de tres capas, validando la microsegmentación.
3. **Sesión 3** — Sobre la misma red del Laboratorio 2, se ejecutan escaneos SCA/SAST/DAST/IAST contenerizados en ACI contra aplicaciones deliberadamente vulnerables, cerrando el ciclo hallazgo → remediación → re-escaneo.
4. **Sesión 4** - En Construcción

Cada guía incluye: objetivos, prerrequisitos, arquitectura de referencia, pasos con comandos de Azure CLI (y equivalentes por portal), preguntas de verificación, solución de problemas frecuentes, checklist de finalización y referencias oficiales.

## Requisitos generales

- Suscripción de Azure con permisos de **Owner** (o *Contributor* + *User Access Administrator*) — sirve la suscripción gratuita o Azure for Students.
- Permisos en Microsoft Entra ID para crear usuarios y grupos.
- Acceso a **Azure Cloud Shell** o Azure CLI instalado localmente.
- Navegador web actualizado (Edge, Chrome o Firefox).
- Herramientas adicionales según la sesión: cliente SSH, Visual Studio Code, Git, cliente de Tailscale (ver [`Herramientas.md`](./Herramientas.md) para el listado completo con enlaces de descarga).

> ⚠️ Varios laboratorios crean recursos de pago por hora en Azure (App Service, VMs, Azure SQL, ACI, etc.). Cada guía incluye una sección de **limpieza de recursos** al final: ejecútala siempre para evitar consumo de crédito.

## Cómo usar este repositorio

```bash
git clone https://github.com/malevarro/DevSecOps2026.git
cd DevSecOps2026
```

Abre la guía de la sesión correspondiente y sigue las actividades en orden; cada una indica la duración estimada y el resultado esperado antes de continuar con la siguiente.

## Licencia y uso

Material de uso académico, elaborado para el curso de DevSecOps. Si reutilizas o adaptas estas guías, por favor conserva la referencia al autor original.
