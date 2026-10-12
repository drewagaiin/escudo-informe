#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Pruebas de escudo-informe.  python3 -m unittest -v"""
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FIX = os.path.join(HERE, "fixtures")
PROG = os.path.join(ROOT, "escudo-informe.py")

spec = importlib.util.spec_from_file_location("ei", PROG)
ei = importlib.util.module_from_spec(spec)
sys.modules["ei"] = ei
spec.loader.exec_module(ei)


def run(args, stdin=None):
    r = subprocess.run([sys.executable, PROG] + args, input=stdin,
                       capture_output=True, text=True)
    return r.returncode, r.stdout, r.stderr


class Normalizacion(unittest.TestCase):
    def test_ssh_alerts(self):
        doc = {"tool": "ssh-sentinel", "host": "srv",
               "alerts": [{"severity": "critical", "id": "SSH-X", "title": "t", "ip": "1.2.3.4"},
                          {"severity": "low", "id": "SSH-Y", "title": "u", "ip": "-"}]}
        hs = list(ei.hallazgos_de_doc(doc))
        self.assertEqual(len(hs), 2)
        self.assertEqual(hs[0].sev, "critico")
        self.assertEqual(hs[1].sev, "bajo")

    def test_correo_email(self):
        doc = {"tool": "correo-escudo", "type": "email", "verdict": "PELIGROSO",
               "verdict_code": "dangerous", "file": "/a/b/fraude.eml"}
        hs = list(ei.hallazgos_de_doc(doc))
        self.assertEqual(hs[0].sev, "alto")
        self.assertEqual(hs[0].target, "fraude.eml")

    def test_correo_clean_se_ignora(self):
        doc = {"tool": "correo-escudo", "type": "email", "verdict_code": "clean"}
        self.assertEqual(list(ei.hallazgos_de_doc(doc)), [])

    def test_cuentas_finding(self):
        doc = {"tool": "cuentas-escudo", "type": "finding", "severity": "critico",
               "code": "BRUTE-SUCCESS", "message": "m", "user": "a@e.com"}
        hs = list(ei.hallazgos_de_doc(doc))
        self.assertEqual(hs[0].sev, "critico")
        self.assertEqual(hs[0].target, "a@e.com")

    def test_windows_finding(self):
        doc = {"tool": "windows-escudo", "type": "finding", "severity": "medio",
               "code": "LSA-UNPROTECTED", "title": "t", "host": "PC1"}
        hs = list(ei.hallazgos_de_doc(doc))
        self.assertEqual(hs[0].sev, "medio")
        self.assertEqual(hs[0].target, "PC1")

    def test_summary_y_basura_se_ignoran(self):
        self.assertEqual(list(ei.hallazgos_de_doc({"type": "summary"})), [])
        self.assertEqual(list(ei.hallazgos_de_doc({"cosa": 1})), [])
        self.assertEqual(list(ei.hallazgos_de_doc("no soy dict")), [])


class Formatos(unittest.TestCase):
    def test_jsonlines(self):
        txt = "\n".join([
            json.dumps({"tool": "cuentas-escudo", "type": "finding", "severity": "alto", "code": "X", "message": "m"}),
            json.dumps({"tool": "cuentas-escudo", "type": "summary"}),
        ])
        docs = list(ei.iter_json_docs(txt))
        self.assertEqual(len(docs), 2)

    def test_objeto_unico(self):
        docs = list(ei.iter_json_docs('{"tool":"ssh-sentinel","alerts":[]}'))
        self.assertEqual(len(docs), 1)

    def test_array(self):
        docs = list(ei.iter_json_docs('[{"a":1},{"b":2}]'))
        self.assertEqual(len(docs), 2)

    def test_lineas_malas_se_saltan(self):
        txt = '{"ok":1}\nesto no es json\n{"ok":2}'
        self.assertEqual(len(list(ei.iter_json_docs(txt))), 2)


class ResumenYNota(unittest.TestCase):
    def mk(self, sevs):
        return [ei.Hallazgo("t", s, "C", "titulo") for s in sevs]

    def test_vacio_es_A(self):
        r = ei.resumir([])
        self.assertEqual((r.grade, r.code, r.verdict), ("A", 0, "BIEN"))

    def test_critico_es_F(self):
        r = ei.resumir(self.mk(["critico", "bajo"]))
        self.assertEqual((r.grade, r.code), ("F", 3))

    def test_alto_es_D(self):
        r = ei.resumir(self.mk(["alto", "medio"]))
        self.assertEqual((r.grade, r.code), ("D", 3))

    def test_medio_es_C(self):
        r = ei.resumir(self.mk(["medio", "bajo"]))
        self.assertEqual((r.grade, r.code), ("C", 1))

    def test_prioridades_solo_alto_y_critico(self):
        hs = self.mk(["critico", "alto", "medio", "bajo"])
        top = ei.prioridades(hs)
        self.assertTrue(all(ei.SEV_ORDER[h.sev] >= 3 for h in top))
        self.assertEqual(top[0].sev, "critico")


class Integracion(unittest.TestCase):
    def _fx(self, name):
        return os.path.join(FIX, name)

    def test_cli_sobre_fixtures(self):
        import glob
        archivos = glob.glob(os.path.join(FIX, "*.json"))
        self.assertTrue(archivos, "faltan fixtures")
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "informe.html")
            c, so, se = run(archivos + ["-o", out])
            self.assertEqual(c, 3)   # los fixtures tienen cosas graves
            self.assertIn("Veredicto", so)
            with open(out, encoding="utf-8") as f:
                htmltxt = f.read()
            self.assertIn("<!doctype html>", htmltxt)
            self.assertIn("Informe de seguridad", htmltxt)

    def test_stdin(self):
        data = json.dumps({"tool": "windows-escudo", "type": "finding",
                           "severity": "critico", "code": "SMB1-ON", "title": "x", "host": "PC"})
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "i.html")
            c, so, se = run(["-", "-o", out], stdin=data)
            self.assertEqual(c, 3)

    def test_sin_argumentos_error(self):
        c, so, se = run([])
        self.assertEqual(c, 2)

    def test_archivo_inexistente(self):
        c, so, se = run(["/no/existe.json", "-o", "/tmp/x.html"])
        self.assertEqual(c, 2)


class Seguridad(unittest.TestCase):
    def test_html_escapado(self):
        # Un título con HTML no debe inyectar etiquetas en el informe.
        doc = {"tool": "windows-escudo", "type": "finding", "severity": "alto",
               "code": "<script>", "title": "<img src=x onerror=alert(1)>", "host": "PC"}
        hs = list(ei.hallazgos_de_doc(doc))
        r = ei.resumir(hs)
        htmltxt = ei.render_html(hs, r, "Empresa <b>")
        self.assertNotIn("<script>", htmltxt)
        self.assertNotIn("<img src=x", htmltxt)
        self.assertIn("&lt;", htmltxt)

    def test_symlink_rechazado(self):
        d = tempfile.mkdtemp()
        objetivo = os.path.join(d, "real.html")
        enlace = os.path.join(d, "informe.html")
        with open(objetivo, "w") as f:
            f.write("previo")
        try:
            os.symlink(objetivo, enlace)
        except OSError:
            self.skipTest("symlinks no soportados")
        data = json.dumps({"tool": "windows-escudo", "type": "finding",
                           "severity": "bajo", "code": "X", "title": "t"})
        c, so, se = run(["-", "-o", enlace], stdin=data)
        self.assertEqual(c, 2)
        with open(objetivo) as f:
            self.assertEqual(f.read(), "previo")


class Regresiones(unittest.TestCase):
    def test_no_doble_conteo(self):
        import glob
        archivos = glob.glob(os.path.join(FIX, "*.json"))
        uno = ei.cargar([archivos[0]])
        dos = ei.cargar([archivos[0], archivos[0]])   # mismo archivo repetido
        self.assertEqual(len(uno), len(dos))

    def test_solo_info_texto(self):
        hs = [ei.Hallazgo("t", "info", "X", "t")]
        r = ei.resumir(hs)
        self.assertEqual(r.grade, "A")
        self.assertIn("informativos", ei.frase_resumen(r))


class GuiaTecnica(unittest.TestCase):
    def test_remedio_codigo_conocido(self):
        que, pasos = ei.remedio_de("SMB1-ON", "windows-escudo")
        self.assertIn("SMBv1", que)
        self.assertTrue(pasos)

    def test_remedio_por_familia(self):
        # un código de correo no listado explícito cae en su familia LINK-
        que, pasos = ei.remedio_de("LINK-PUNY", "correo-escudo")
        self.assertTrue(pasos)
        self.assertEqual((que, pasos), ei.REMEDIOS_FAMILIA["LINK-"])

    def test_remedio_por_herramienta(self):
        que, pasos = ei.remedio_de("CODIGO-INVENTADO", "cuentas-escudo")
        self.assertEqual(que, "")
        self.assertEqual(pasos, ei.REMEDIOS_TOOL["cuentas-escudo"])

    def test_remedio_desconocido_sin_tool(self):
        que, pasos = ei.remedio_de("XYZ", "")
        self.assertEqual(que, "")
        self.assertTrue(pasos)   # siempre devuelve algún paso

    def test_correo_expande_hallazgos_internos(self):
        doc = {"tool": "correo-escudo", "type": "email", "verdict": "PELIGROSO",
               "verdict_code": "dangerous", "file": "/x/fraude.eml",
               "findings": [{"id": "BEC-CONFIRMED", "severity": "critical", "title": "t"},
                            {"id": "ATT-EXEC", "severity": "critical", "title": "u"}]}
        hs = list(ei.hallazgos_de_doc(doc))
        self.assertEqual(len(hs), 1)              # para el cliente: 1 correo
        items = ei.items_tecnicos(hs)             # para el técnico: 2 problemas
        codes = {it["code"] for it in items}
        self.assertEqual(codes, {"BEC-CONFIRMED", "ATT-EXEC"})

    def test_items_ordenados_por_gravedad(self):
        hs = [ei.Hallazgo("windows-escudo", "bajo", "X", "t"),
              ei.Hallazgo("windows-escudo", "critico", "SMB1-ON", "t")]
        items = ei.items_tecnicos(hs)
        self.assertEqual(items[0]["sev"], "critico")

    def test_render_tecnico_escapa_html(self):
        doc = {"tool": "windows-escudo", "type": "finding", "severity": "alto",
               "code": "<script>", "title": "<img src=x onerror=alert(1)>", "host": "PC"}
        hs = list(ei.hallazgos_de_doc(doc))
        r = ei.resumir(hs)
        htmltxt = ei.render_tecnico(hs, r, "Empresa <b>")
        self.assertNotIn("<script>", htmltxt)
        self.assertNotIn("<img src=x", htmltxt)
        self.assertIn("Cómo resolver", htmltxt)

    def test_cli_genera_guia_tecnica(self):
        data = json.dumps({"tool": "windows-escudo", "type": "finding",
                           "severity": "critico", "code": "SMB1-ON", "title": "x", "host": "PC"})
        with tempfile.TemporaryDirectory() as d:
            cli = os.path.join(d, "cliente.html")
            tec = os.path.join(d, "tec.html")
            c, so, se = run(["-", "-o", cli, "--tecnico", tec], stdin=data)
            self.assertEqual(c, 3)
            self.assertTrue(os.path.exists(tec))
            with open(tec, encoding="utf-8") as f:
                t = f.read()
            self.assertIn("Guía técnica", t)
            self.assertIn("Desactiva SMBv1", t)

    def test_cli_tecnico_auto_nombre(self):
        data = json.dumps({"tool": "windows-escudo", "type": "finding",
                           "severity": "bajo", "code": "X", "title": "x", "host": "PC"})
        with tempfile.TemporaryDirectory() as d:
            cli = os.path.join(d, "informe.html")
            c, so, se = run(["-", "-o", cli, "--tecnico"], stdin=data)
            self.assertEqual(c, 1)
            self.assertTrue(os.path.exists(os.path.join(d, "informe-tecnico.html")))


if __name__ == "__main__":
    unittest.main(verbosity=2)
