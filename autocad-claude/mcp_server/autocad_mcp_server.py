"""
Servidor MCP para AutoCAD 2026 (Windows) — lectura y escritura del dibujo
activo via automatización COM (ActiveX/Automation).

Requisitos:
  - Windows + AutoCAD 2026 (full; LT no expone COM) abierto y con un dibujo.
  - pip install "mcp[cli]" pywin32

Prueba rápida:
  python autocad_mcp_server.py            # se conecta por stdio (lo usa Claude)
  npx @modelcontextprotocol/inspector python autocad_mcp_server.py   # depuración

Seguridad:
  - Las herramientas de escritura modifican el dibujo ABIERTO (usa GUARDAR y
    copia de seguridad antes de experimentar).
  - run_command() está DESACTIVADA por defecto; actívala solo de forma
    consciente con AUTOCAD_MCP_ALLOW_COMMANDS=1 (ejecuta comandos arbitrarios).
"""
from __future__ import annotations

import os
from typing import Any

import pythoncom
import win32com.client
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("autocad")

# Cadena tolerante a versiones: 2026 = 25.1, 2025 = 25.0, 2024 = 24.3, ...
_PROGIDS = (
    "AutoCAD.Application.25.1",
    "AutoCAD.Application.25",
    "AutoCAD.Application.24.3",
    "AutoCAD.Application",
)

ALLOW_COMMANDS = os.environ.get("AUTOCAD_MCP_ALLOW_COMMANDS", "") == "1"


# --------------------------------------------------------------------------
# Utilidades COM
# --------------------------------------------------------------------------
def _com() -> None:
    """Inicializa el apartamento COM en el hilo actual (FastMCP usa threadpool)."""
    pythoncom.CoInitialize()


def _acad() -> Any:
    _com()
    last_err: Exception | None = None
    for pid in _PROGIDS:
        try:
            return win32com.client.GetActiveObject(pid)
        except Exception as e:  # ProgID no registrado / AutoCAD cerrado
            last_err = e
    raise RuntimeError(
        "No se encontró una instancia de AutoCAD en ejecución. "
        "Abre AutoCAD 2026 e inténtalo de nuevo."
    ) from last_err


def _doc() -> Any:
    doc = _acad().ActiveDocument
    if doc is None:
        raise RuntimeError("AutoCAD está abierto pero no hay ningún documento activo.")
    return doc


def _pt(x: float, y: float, z: float = 0.0):
    """AutoCAD COM espera SAFEARRAY de doubles para los puntos."""
    return win32com.client.VARIANT(
        pythoncom.VT_ARRAY | pythoncom.VT_R8, [float(x), float(y), float(z)]
    )


def _num(v: Any) -> Any:
    """Convierte tuplas/variantes COM a tipos JSON-serIALIZABLES."""
    if isinstance(v, (tuple, list)):
        return [round(float(c), 6) for c in v]
    if isinstance(v, float):
        return round(v, 6)
    return v


def _summary(e: Any) -> dict[str, Any]:
    info: dict[str, Any] = {"handle": e.Handle, "type": e.ObjectName, "layer": e.Layer}
    try:
        info["color"] = e.TrueColor.ColorValue if e.Color == 256 else e.Color
    except Exception:
        pass
    props = {
        "AcDbLine": ["StartPoint", "EndPoint", "Length"],
        "AcDbCircle": ["Center", "Radius", "Circumference", "Area"],
        "AcDbArc": ["Center", "Radius", "StartAngle", "EndAngle"],
        "AcDbEllipse": ["Center", "MajorAxis", "MinorAxis"],
        "AcDbPolyline": ["Length", "Closed", "Area"],
        "AcDbText": ["InsertionPoint", "TextString", "Height", "Rotation"],
        "AcDbMText": ["Location", "Text", "Height", "Width"],
        "AcDbBlockReference": ["InsertionPoint", "Name", "Rotation"],
        "AcDbHatch": ["Pattern", "PatternScale"],
        "AcDbSpline": ["Length", "Closed"],
    }.get(e.ObjectName, [])
    for p in props:
        try:
            info[p] = _num(getattr(e, p))
        except Exception:
            pass
    return info


# --------------------------------------------------------------------------
# Herramientas de SESIÓN / LECTURA
# --------------------------------------------------------------------------
@mcp.tool()
def status() -> dict:
    """Estado de la sesión: documento activo, nº de entidades, unidades."""
    _com()
    doc = _doc()
    acad = _acad()
    return {
        "acad_version": acad.Version,
        "document": doc.Name,
        "path": doc.FullName,
        "model_space_entities": doc.ModelSpace.Count,
        "layout_count": doc.Layouts.Count,
        "insunits": doc.GetVariable("INSUNITS"),  # 0=Sin unidad 1=pulg 4=mm 5=cm 6=m
        "lunits": doc.GetVariable("LUNITS"),
        "saved": not doc.ReadOnly,
    }


@mcp.tool()
def list_entities(
    start: int = 0,
    count: int = 50,
    layer: str | None = None,
    entity_type: str | None = None,
) -> dict:
    """Lista entidades del espacio modelo (paginado) con sus propiedades.

    entity_type: filtro parcial por objeto ACad, p.ej. 'AcDbLine', 'AcDbText'.
    """
    _com()
    doc = _doc()
    ms = doc.ModelSpace
    total = ms.Count
    out, scanned = [], 0
    i = max(0, start)
    while i < total and len(out) < count:
        e = ms.Item(i)
        scanned += 1
        ok = (layer is None or e.Layer == layer) and (
            entity_type is None or entity_type.lower() in e.ObjectName.lower()
        )
        if ok:
            out.append(_summary(e))
        i += 1
    return {"total": total, "from_index": start, "returned": len(out), "entities": out}


@mcp.tool()
def get_entity(handle: str) -> dict:
    """Devuelve TODAS las propiedades de una entidad a partir de su handle."""
    _com()
    doc = _doc()
    e = doc.HandleToObject(handle)
    info = {"handle": e.Handle, "type": e.ObjectName, "layer": e.Layer}
    for p in dir(e):
        if p.startswith("_") or p in ("Application", "Document", "Database"):
            continue
        try:
            v = getattr(e, p)
            if not callable(v):
                info[p] = _num(v)
        except Exception:
            pass
    if e.ObjectName == "AcDbBlockReference":
        try:
            info["attributes"] = {
                a.Tag: a.TextString for a in e.GetAttributes()
            }
        except Exception:
            pass
    return info


@mcp.tool()
def list_layers() -> list[dict]:
    """Lista capas con color, visibilidad y número aproximado de entidades."""
    _com()
    doc = _doc()
    out = []
    for i in range(doc.Layers.Count):
        l = doc.Layers.Item(i)
        out.append(
            {
                "name": l.Name,
                "color": l.Color,
                "layer_on": bool(l.LayerOn),
                "frozen": bool(l.Freeze),
                "locked": bool(l.Lock),
            }
        )
    return out


@mcp.tool()
def list_blocks() -> list[dict]:
    """Lista definiciones de bloques del dibujo (sin dependencias internas)."""
    _com()
    doc = _doc()
    out = []
    for i in range(doc.Blocks.Count):
        b = doc.Blocks.Item(i)
        if b.Name.startswith("*") or b.IsXRef:
            continue
        out.append({"name": b.Name, "origin": _num(b.InsertionPoint)})
    return out


@mcp.tool()
def selection_set_info() -> dict:
    """Entidades actualmente seleccionadas en la UI de AutoCAD."""
    _com()
    doc = _doc()
    ss = doc.ActiveSelectionSet
    if ss is None or ss.Count == 0:
        return {"count": 0, "entities": [], "note": "No hay selección activa."}
    return {"count": ss.Count, "entities": [_summary(ss.Item(i)) for i in range(min(ss.Count, 100))]}


# --------------------------------------------------------------------------
# Herramientas de ESCRITURA
# --------------------------------------------------------------------------
def _ensure_layer(doc, name: str | None) -> str:
    if not name:
        return "0"
    try:
        doc.Layers.Add(name)
    except Exception:
        pass  # ya existe
    return name


@mcp.tool()
def draw_line(x1: float, y1: float, x2: float, y2: float, layer: str = "0") -> dict:
    """Dibuja una línea recta en el espacio modelo."""
    _com()
    doc = _doc()
    e = doc.ModelSpace.AddLine(_pt(x1, y1), _pt(x2, y2))
    e.Layer = _ensure_layer(doc, layer)
    return {"handle": e.Handle, "type": e.ObjectName, "layer": e.Layer}


@mcp.tool()
def draw_polyline(points: list[list[float]], closed: bool = False, layer: str = "0") -> dict:
    """Dibuja una polilínea. points = [[x,y], [x,y], ...] en unidades de dibujo."""
    _com()
    doc = _doc()
    flat: list[float] = []
    for p in points:
        flat.extend([float(p[0]), float(p[1])])
    pts = win32com.client.VARIANT(pythoncom.VT_ARRAY | pythoncom.VT_R8, flat)
    e = doc.ModelSpace.AddLightWeightPolyline(pts)
    if closed:
        e.Closed = True
    e.Layer = _ensure_layer(doc, layer)
    return {"handle": e.Handle, "vertices": len(points), "closed": closed}


@mcp.tool()
def draw_circle(cx: float, cy: float, radius: float, layer: str = "0") -> dict:
    """Dibuja una circunferencia."""
    _com()
    doc = _doc()
    e = doc.ModelSpace.AddCircle(_pt(cx, cy), float(radius))
    e.Layer = _ensure_layer(doc, layer)
    return {"handle": e.Handle, "center": [cx, cy], "radius": radius}


@mcp.tool()
def draw_arc(cx: float, cy: float, radius: float, start_angle_deg: float, end_angle_deg: float, layer: str = "0") -> dict:
    """Arco en grados (antihorario desde +X)."""
    _com()
    import math

    doc = _doc()
    e = doc.ModelSpace.AddArc(
        _pt(cx, cy), float(radius),
        math.radians(start_angle_deg), math.radians(end_angle_deg),
    )
    e.Layer = _ensure_layer(doc, layer)
    return {"handle": e.Handle}


@mcp.tool()
def add_text(x: float, y: float, height: float, text: str, rotation_deg: float = 0.0, layer: str = "0") -> dict:
    """Añade texto de una línea (TEXT/DBTEXT)."""
    _com()
    import math

    doc = _doc()
    e = doc.ModelSpace.AddText(str(text), _pt(x, y), float(height))
    e.Rotation = math.radians(rotation_deg)
    e.Layer = _ensure_layer(doc, layer)
    return {"handle": e.Handle, "text": text}


@mcp.tool()
def add_mtext(x: float, y: float, text: str, width: float = 100.0, height: float = 2.5, layer: str = "0") -> dict:
    """Añade texto multicadena (MTEXT) con ancho de párrafo."""
    _com()
    doc = _doc()
    e = doc.ModelSpace.AddMText(_pt(x, y), float(width), str(text))
    try:
        e.Height = float(height)
    except Exception:
        pass
    e.Layer = _ensure_layer(doc, layer)
    return {"handle": e.Handle}


@mcp.tool()
def insert_block(name: str, x: float, y: float, scale: float = 1.0, rotation_deg: float = 0.0, layer: str = "0") -> dict:
    """Inserta una referencia de bloque ya definido en el dibujo."""
    _com()
    import math

    doc = _doc()
    blk = doc.Blocks.Item(name)  # excepción si no existe
    e = doc.ModelSpace.InsertBlock(_pt(x, y), name, float(scale), float(scale), float(scale), math.radians(rotation_deg))
    e.Layer = _ensure_layer(doc, layer)
    return {"handle": e.Handle, "block": blk.Name}


@mcp.tool()
def set_block_attributes(handle: str, attributes: dict[str, str]) -> dict:
    """Actualiza los ATTRIB de una referencia de bloque. attributes = {TAG: valor}."""
    _com()
    doc = _doc()
    e = doc.HandleToObject(handle)
    if e.ObjectName != "AcDbBlockReference":
        raise ValueError(f"{handle} no es un bloque (es {e.ObjectName}).")
    changed = {}
    for a in e.GetAttributes():
        if a.Tag in attributes:
            a.TextString = str(attributes[a.Tag])
            changed[a.Tag] = attributes[a.Tag]
    return {"handle": handle, "updated": changed}


@mcp.tool()
def modify_entity(handle: str, layer: str | None = None, color: int | None = None,
                 visible: bool | None = None) -> dict:
    """Cambia capa/color/visibilidad de una entidad existente."""
    _com()
    doc = _doc()
    e = doc.HandleToObject(handle)
    if layer is not None:
        _ensure_layer(doc, layer)
        e.Layer = layer
    if color is not None:
        e.Color = int(color)
    if visible is not None:
        e.Visible = bool(visible)
    return {"handle": handle, "ok": True}


@mcp.tool()
def move_entity(handle: str, dx: float, dy: float, dz: float = 0.0) -> dict:
    _com()
    doc = _doc()
    e = doc.HandleToObject(handle)
    e.Move(_pt(0, 0, 0), _pt(dx, dy, dz))
    return {"handle": handle, "moved_by": [dx, dy, dz]}


@mcp.tool()
def rotate_entity(handle: str, base_x: float, base_y: float, angle_deg: float) -> dict:
    _com()
    import math

    doc = _doc()
    e = doc.HandleToObject(handle)
    e.Rotate(_pt(base_x, base_y), math.radians(angle_deg))
    return {"handle": handle, "angle_deg": angle_deg}


@mcp.tool()
def delete_entity(handle: str) -> dict:
    _com()
    doc = _doc()
    e = doc.HandleToObject(handle)
    info = _summary(e)
    e.Delete()
    return {"deleted": info}


@mcp.tool()
def create_layer(name: str, color: int = 256) -> dict:
    _com()
    doc = _doc()
    l = doc.Layers.Add(name)
    l.Color = int(color)
    return {"layer": l.Name, "created": True}


@mcp.tool()
def zoom_extents() -> dict:
    """Encuadre 'Zoom Extends' para ver el resultado."""
    _com()
    doc = _doc()
    doc.Application.Update()
    doc.ZoomExtents()
    return {"ok": True}


@mcp.tool()
def save_document(path: str | None = None) -> dict:
    """Guarda el documento (SaveAs si se indica ruta .dwg)."""
    _com()
    doc = _doc()
    if path:
        doc.SaveAs(path)
    else:
        doc.Save()
    return {"saved_to": doc.FullName}


@mcp.tool()
def undo_last() -> dict:
    """Deshace la última operación (UNDO Back)."""
    _com()
    doc = _doc()
    doc.SendStringToExecute("_.UNDO\n_Back\n", True, False, True)
    return {"ok": True, "note": "Si la vista no se actualiza, pulsa Regenerar (REGEN)."}


@mcp.tool()
def run_command(command: str) -> dict:
    """[DESHABILITADA salvo AUTOCAD_MCP_ALLOW_COMMANDS=1] Ejecuta un comando de
    AutoCAD en la línea de órdenes, p.ej. '_-PURGE _All _N '. Úsalo solo en
    copias de prueba del dibujo."""
    if not ALLOW_COMMANDS:
        raise PermissionError(
            "run_command desactivada. Actívala con AUTOCAD_MCP_ALLOW_COMMANDS=1 "
            "solo si entiendes el riesgo: ejecuta comandos arbitrarios."
        )
    _com()
    doc = _doc()
    doc.SendStringToExecute(command.strip() + "\n", True, False, False)
    return {"sent": command, "ok": True}


if __name__ == "__main__":
    mcp.run()  # transporte stdio por defecto
