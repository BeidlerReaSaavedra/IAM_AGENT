// Opción B — Esqueleto de plugin .NET 8 para AutoCAD 2026 (Anthropic API directa).
// Compilar contra las DLL de "ObjectARX/.NET SDK for AutoCAD 2026":
//   Autodesk.AutoCAD.dll, Autodesk.AutoCAD.Runtime.dll, acmgd, accoremgd
// (CopyLocal=false; NETLOAD desde AutoCAD; también puede cargarse con REGAPP).
//
// Proyecto csproj: net8.0-windows, UseWindowsForms=true, <PrivateAssets> en refs.
//
// Flujo: contexto del dibujo -> Claude (tool use) -> acciones -> Transaction .NET
// => lectura Y escritura con UNDO transaccional de AutoCAD.

using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using Autodesk.AutoCAD.ApplicationServices;
using Autodesk.AutoCAD.DatabaseServices;
using Autodesk.AutoCAD.EditorInput;
using Autodesk.AutoCAD.Geometry;
using Autodesk.AutoCAD.Runtime;

namespace ClaudeBridge
{
    public class Commands
    {
        // ⚠ En producción: variable de entorno / Vault, nunca en el binario.
        static readonly string ApiKey =
            Environment.GetEnvironmentVariable("ANTHROPIC_API_KEY") ?? "";

        [CommandMethod("CLAUDEPROMPT", CommandSession.Modal)]
        public void Ask()
        {
            var doc  = Application.DocumentManager.MdiActiveDocument;
            var ed   = doc.Editor;
            var pr   = ed.GetString("\nDile algo a Claude (p.ej. 'dibuja una losa 6x4 m'): ");
            if (pr.Status != PromptStatus.OK || string.IsNullOrWhiteSpace(pr.StringResult))
                return;

            // 1) LECTURA: resumen del dibujo para el modelo (capas + primeras entidades)
            string context = CollectContext(doc.Database);

            // 2) Claude decide qué tools invocar (draw_line, draw_text, set_layer...)
            string json = ClaudeApi.Ask(ApiKey, context, pr.StringResult).GetAwaiter().GetResult();

            // 3) ESCRITURA: ejecutar las acciones dentro de una transacción = 1 UNDO
            using (doc.LockDocument())
            using (var tr = doc.Database.TransactionManager.StartTransaction())
            {
                var bt = (BlockTable)tr.GetObject(doc.Database.BlockTableId, OpenMode.ForRead);
                var ms = (BlockTableRecord)tr.GetObject(bt["ModelSpace"], OpenMode.ForWrite);
                foreach (var action in JsonSerializer.Deserialize<List<Action3>>(json))
                {
                    switch (action.Tool)
                    {
                        case "draw_line":
                            ms.AppendEntity(new Line(
                                new Point3d(action.A[0], action.A[1], 0),
                                new Point3d(action.B[0], action.B[1], 0)) { Layer = action.Layer ?? "0" });
                            tr.AddNewlyCreatedDBObject(ms.LastEntity!, true);
                            break;
                        case "draw_text":
                            var t = new DBText { Position = new Point3d(action.A[0], action.A[1], 0),
                                                 Height = action.H ?? 0.25, TextString = action.Text,
                                                 Layer = action.Layer ?? "0" };
                            ms.AppendEntity(t); tr.AddNewlyCreatedDBObject(t, true);
                            break;
                        // ... círculos, polilíneas, borrado por Handle, etc.
                    }
                }
                tr.Commit(); // un solo paso de UNDO para todo lo generado por IA
            }
            ed.WriteMessage("\nClaude ha modificado el dibujo. Revisa antes de guardar.\n");
        }

        static string CollectContext(Database db)
        {
            var sb = new StringBuilder("CAPAS: ");
            using var tr = db.TransactionManager.StartTransaction();
            var lt = (LayerTable)tr.GetObject(db.LayerTableId, OpenMode.ForRead);
            foreach (var id in lt) sb.Append(((LayerTableRecord)tr.GetObject(id, OpenMode.ForRead)).Name + ", ");
            var ps = new PromptSelectionResult(); // (puede añadirse SelectAll filtrado)
            sb.Append($"\nENTIDADES EN MODELSPACE: {CountModelSpace(db, tr)}");
            tr.Commit();
            return sb.ToString();
        }

        static int CountModelSpace(Database db, Transaction tr)
        {
            var bt = (BlockTable)tr.GetObject(db.BlockTableId, OpenMode.ForRead);
            var ms = (BlockTableRecord)tr.GetObject(bt[BlockTableRecord.ModelSpace], OpenMode.ForRead);
            int n = 0; using var e = ms.GetEnumerator(); while (e.MoveNext()) n++;
            return n;
        }

        record Action3(string Tool, double[] A, double[] B, double? H, string Text, string Layer);
    }

    // Cliente mínimo de la API de Anthropic con "tool use" simplificado:
    // pedimos al modelo que responda SOLO con un array JSON de acciones.
    public static class ClaudeApi
    {
        static readonly HttpClient Http = new();
        const string System = "Eres un asistente de CAD. Devuelve EXCLUSIVAMENTE un " +
            "array JSON de acciones: [{\"tool\":\"draw_line\",\"a\":[x,y],\"b\":[x,y]," +
            "\"layer\":\"0\"},{\"tool\":\"draw_text\",\"a\":[x,y],\"h\":0.25," +
            "\"text\":\"...\"}] en metros. Nada de prosa.";

        public static async System.Threading.Tasks.Task<string> Ask(string key, string ctx, string user)
        {
            var body = JsonSerializer.Serialize(new
            {
                model = "claude-sonnet-4-5",
                max_tokens = 2048,
                system = System,
                messages = new object[] {
                    new { role = "user",
                          content = "CONTEXTO DEL DIBUJO:\n" + ctx + "\n\nPETICION:\n" + user }
                }
            });
            using var req = new HttpRequestMessage(HttpMethod.Post, "https://api.anthropic.com/v1/messages");
            req.Headers.Add("x-api-key", key);
            req.Headers.Add("anthropic-version", "2023-06-01");
            req.Content = new StringContent(body, Encoding.UTF8, "application/json");
            var res = await Http.SendAsync(req);
            res.EnsureSuccessStatusCode();
            using var doc = JsonDocument.Parse(await res.Content.ReadAsStringAsync());
            string text = doc.RootElement.GetProperty("content")[0].GetProperty("text").GetString()!;
            int i = text.IndexOf('['), j = text.LastIndexOf(']');
            return (i >= 0 && j > i) ? text[i..(j + 1)] : "[]";
        }
    }
}
