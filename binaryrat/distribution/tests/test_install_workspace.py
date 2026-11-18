"""Exercise bundled workspace configuration without a user application profile."""

from io import BytesIO
from pathlib import Path
import sys
import unittest
from xml.etree import ElementTree as ET
from zipfile import ZipFile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from install_workspace import edit_workspace, edit_workspace_jar

TEMPLATE = b"""<?xml version="1.0" encoding="UTF-8"?>
<TOOL_CONFIG CONFIG_NAME="NO_LONGER_USED">
    <SUPPORTED_DATA_TYPE CLASS_NAME="ghidra.program.model.listing.Program" />
    <TOOL TOOL_NAME="CodeBrowser">
        <OPTIONS />
        <PACKAGE NAME="Ghidra Core"><INCLUDE CLASS="ExistingPlugin"/></PACKAGE>
        <PACKAGE NAME="BSim" />
        <ROOT_NODE WIDTH="1000" HEIGHT="800" />
    </TOOL>
</TOOL_CONFIG>
"""


class WorkspaceTests(unittest.TestCase):
    def test_keeps_standard_associations_layout_and_packages(self):
        edited = edit_workspace(TEMPLATE)
        self.assertEqual(edit_workspace(edited), edited)
        original = ET.fromstring(TEMPLATE)
        changed = ET.fromstring(edited)
        tool = changed.find("TOOL")
        package = tool.find("./PACKAGE[@NAME='BinaryRat']")
        self.assertEqual(
            [entry.get("CLASS") for entry in package],
            ["binaryrat.desktop.BinaryRatWorkspacePlugin", "binaryrat.desktop.BinaryRatForegroundPlugin"],
        )
        tool.remove(package)
        self.assertEqual(ET.tostring(changed), ET.tostring(original))

    def test_rejects_an_unexpected_or_conflicting_template(self):
        for content in (
            b'<!DOCTYPE TOOL_CONFIG><TOOL_CONFIG/>',
            b"\xff",
            b"<TOOL_CONFIG>",
            TEMPLATE.replace(b'CodeBrowser', b'Debugger'),
            TEMPLATE.replace(b'NAME="BSim"', b'NAME="BinaryRat"'),
            TEMPLATE.replace(b'<PACKAGE NAME="BSim" />', b'<PLUGIN CLASS="ExistingPlugin" />'),
        ):
            with self.subTest(content=content), self.assertRaises(ValueError):
                edit_workspace(content)

    def test_edits_only_the_canonical_jar_resource(self):
        src = BytesIO()
        with ZipFile(src, "w") as jar:
            jar.writestr("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\r\n")
            jar.writestr("defaultTools/CodeBrowser.tool", TEMPLATE)
            jar.writestr("UserAgreement.html", b"help page")
        with ZipFile(BytesIO(edit_workspace_jar(src.getvalue()))) as jar:
            self.assertEqual(jar.read("META-INF/MANIFEST.MF"), b"Manifest-Version: 1.0\r\n")
            self.assertEqual(jar.read("UserAgreement.html"), b"help page")
            self.assertEqual(jar.read("defaultTools/CodeBrowser.tool"), edit_workspace(TEMPLATE))

    def test_signed_jar_rejected(self):
        src = BytesIO()
        with ZipFile(src, "w") as jar:
            jar.writestr("defaultTools/CodeBrowser.tool", TEMPLATE)
            jar.writestr("META-INF/RELEASE.RSA", b"signature")
        with self.assertRaisesRegex(ValueError, "signed configuration"):
            edit_workspace_jar(src.getvalue())


if __name__ == "__main__":
    unittest.main()
