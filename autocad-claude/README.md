# Claude ↔ AutoCAD 2026 (lectura + escritura)

Guía y andamiaje para que Claude lea y modifique dibujos de AutoCAD 2026.

**Elige la opción según tu caso:**

| Caso | Opción recomendada |
|---|---|
| AutoCAD 2026 completo, Windows, quieres que Claude Desktop/Code "vea y dibuje" ya | **A — Servidor MCP** (incluida en esta carpeta) |
| Quieres un botón/panel *dentro* de AutoCAD que hable con Claude | **B — Plugin .NET API** |
| AutoCAD **LT** 2024+ (sin COM) | **C — Puente AutoLISP** |
| Sin AutoCAD en la máquina (generar DXF por lotes, Linux/Mac) | **D — ezdxf headless** |

> Nota: AutoCAD para Mac no expone COM/Automation → las opciones A–C requieren Windows.
> A partir de AutoCAD 2027, Autodesk incorpora un asistente de IA que ya usa el
> estándar MCP; el trabajo de esta carpeta será portable a esa versión.

---

## Opción A — Servidor MCP (recomendada)

Model Context Protocol (MCP) es el estándar de Anthropic para dar a Claude
herramientas externas. El servidor MCP de esta carpeta expone AutoCAD vía COM
(automation ActiveX `AutoCAD.Application.25.1` → con fallbacks) como ~20
herramientas de lectura (`status`, `list_entities`, `get_entity`, `list_layers`,
`selection_set_info`…) y escritura (`draw_line`, `draw_polyline`, `add_mtext`,
`insert_block`, `move_entity`, `delete_entity`, `save_document`, `undo_last`…).

### 1. Instalar (en la máquina con AutoCAD)

```powershell
# Python 3.10+ de Windows nativo (no WSL)
py -3 -m venv C:\AutocadIam\.venv
C:\AutocadIam\.venv\Scripts\pip install "mcp[cli]" pywin32
```

Copia `mcp_server/autocad_mcp_server.py` en `C:\AutocadIam\mcp_server\`.

### 2. Conectar con Claude Desktop

Edita `%APPDATA%\Claude\claude_desktop_config.json` (ver
`config/claude_desktop_config.example.json`), cierra y reabre Claude Desktop:

```json
{
  "mcpServers": {
    "autocad": {
      "command": "C:\\AutocadIam\\.venv\\Scripts\\python.exe",
      "args": ["C:\\AutocadIam\\mcp_server\\autocad_mcp_server.py"]
    }
  }
}
```

### 2b. Conectar con Claude Code (alternativa, a menudo mejor para CAD)

```powershell
claude mcp add autocad -s user -- ^
  "C:\AutocadIam\.venv\Scripts\python.exe" ^
  "C:\AutocadIam\mcp_server\autocad_mcp_server.py"
claude mcp list   # debe aparecer autocad ✓
```

Claude Code también acepta un `.mcp.json` en la carpeta del proyecto con la
misma clave `mcpServers`. Ventaja: puede además leer/editar archivos (DCL,
LISP, perfiles) con permisos granulares por sesión.

### 3. Probar

1. Abre AutoCAD 2026 con un dibujo.
2. En Claude: *«¿Qué dibujo tengo abierto y cuántas entidades hay?»* → debe
   llamar a `status`.
3. *«Dibuja un rectángulo 4000x8000 en la capa MURO y pon un texto que diga
   SALA»* → `draw_polyline` + `add_text`.
4. Depuración sin Claude:
   `npx @modelcontextprotocol/inspector python autocad_mcp_server.py`

### Seguridad (importante cuando el modelo puede ESCRIBIR)

- Trabaja sobre una **copia** del DWG o guarda a menudo; `undo_last` solo
  deshace un paso y no siempre sirve con regeneración de vista.
- `run_command` (enviar comandos arbitrarios a la línea de órdenes) está
  bloqueada salvo `AUTOCAD_MCP_ALLOW_COMMANDS=1`.
- Bloquea capas/papeleras con `_LOCK` si quieres limitar a Claude a ciertas capas.

---

## Opción B — Plugin .NET dentro de AutoCAD (Anthropic API directa)

AutoCAD 2026 usa **.NET 8** (`net8.0-windows`, binariamente compatible con
2025; SDK: *AutoCAD .NET API Wizard 2026* de ADN-DevTech). Esquema mínimo:

```csharp
// COMANDOS: CLAUDEPROMPT — envía contexto del dibujo a Claude y ejecuta las
// acciones JSON que devuelve. Referencias: Autodesk.AutoCAD.*.dll (Managed)
[CommandMethod("CLAUDEPROMPT")]
public void Ask()
{
    var doc = Application.DocumentManager.MdiActiveDocument;
    var db  = doc.Database;
    string context = CollectContext(doc);            // capas + entidades (Transaction + SelectAll)
    string answer  = ClaudeApi.SendMessage(context + "\n\nPeticion: " + PromptUser());
    foreach (var a in ParseActions(answer))         // [{tool:"line", pts:[[0,0],[10,0]]}, ...]
        Apply(db, a);                               // API .NET: Line/Circle/DBText, LayerTable...
}
```

`ClaudeApi.SendMessage` = `HttpClient` POST a `https://api.anthropic.com/v1/messages`
(modelo p.ej. `claude-sonnet-4-5`, header `x-api-key`), con *tool use*: declaras
tus propios métodos .NET (`draw_line`, `query_entities`…) como tools en el JSON
de la petición y Claude responde con llamadas que tu plugin ejecuta sobre la
base de datos del dibujo. Esto es exactamente lo que hace el servidor MCP de la
opción A, pero embebido: sin Claude Desktop, con UI propia y sin exponer COM.

Ventaja frente a A: puedes leer selección activa en tiempo real, validar antes
de escribir, registrar todo en `DocumentManager` con undo transaccional
(`doc.TransactionManager` → el UNDO de AutoCAD agrupa el cambio completo).

## Opción C — AutoCAD LT (sin COM): dispatcher AutoLISP

LT 2024+ soporta AutoLISP pero no `vlax-*`/COM. El patrón (usado por el
proyecto comunitario `puran-water/autocad-mcp`):

1. Cargar en LT un `mcp_dispatch.lsp` que, en bucle, lee `in.json`, ejecuta
   operaciones con `entmake`/`entmod`/`entget`, escribe `out.json`.
2. El servidor MCP (Python) se limita a intercambiar los archivos y hablar MCP.
3. Claude Desktop/Code → MCP → archivos → AutoLISP → dibujo. Lectura
   (`entget (car (entsel))`) y escritura (`entmake`) completas.

## Opción D — Sin AutoCAD (headless, sirve para Mac/Linux)

`ezdxf` lee/escribe DXF y renderiza a PNG/PDF (aproximado). Claude Code con la
skill de archivos basta: *«edita plano.dxf, añade una puerta y regenera el
DXF»*. DWG nativo requiere AutoCAD (o el conversor ODA File Converter).

---

## Estructura de esta carpeta

```
autocad-claude/
├── README.md
├── mcp_server/
│   ├── autocad_mcp_server.py   # servidor MCP -> COM de AutoCAD (op. A)
│   └── requirements.txt
├── config/
│   └── claude_desktop_config.example.json
└── dotnet/
    └── ClaudeBridge.cs         # esqueleto op. B (plugin .NET 8)
```
