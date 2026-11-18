"""Add BinaryRat plugins to the bundled Ghidra 12.2 default CodeBrowser template.

Copyright 2026 YurilLAB
SPDX-License-Identifier: Apache-2.0
"""
from __future__ import annotations

from io import BytesIO
from xml.etree import ElementTree as ET
from zipfile import ZipFile

_WORKSPACE = "defaultTools/CodeBrowser.tool"
_MAX_TEMPLATE_BYTES = 2 * 1024 * 1024
_MAX_JAR_BYTES = 8 * 1024 * 1024
_PACKAGE = "BinaryRat"
_PLUGINS = (
    "binaryrat.desktop.BinaryRatWorkspacePlugin",
    "binaryrat.desktop.BinaryRatForegroundPlugin",
)


def edit_workspace(data: bytes) -> bytes:
    """Preserve the upstream tool name, layout and package configuration."""
    if len(data) > _MAX_TEMPLATE_BYTES:
        raise ValueError("Unexpected default CodeBrowser template")
    xml = data.decode("utf-8-sig")
    if "<!DOCTYPE" in xml.upper():
        raise ValueError("A default workspace must not contain a document type")
    try:
        root = ET.fromstring(xml, parser=ET.XMLParser(target=ET.TreeBuilder(insert_comments=True)))
    except ET.ParseError as error:
        raise ValueError("Invalid XML in the default CodeBrowser template") from error
    tools = root.findall("TOOL")
    if root.tag != "TOOL_CONFIG" or len(tools) != 1 or tools[0].get("TOOL_NAME") != "CodeBrowser":
        raise ValueError("Expected the standard CodeBrowser tool")
    tool = tools[0]
    core = tool.find("./PACKAGE[@NAME='Ghidra Core']")
    if tool.find("PLUGIN") is not None or core is None:
        raise ValueError("Expected a package-based CodeBrowser template")
    installed = tool.findall(f"./PACKAGE[@NAME='{_PACKAGE}']")
    if installed:
        declarations = [child for child in installed[0] if child.tag is not ET.Comment]
        if (len(installed) == 1 and [child.get("CLASS") for child in declarations] == list(_PLUGINS)
                and all(child.tag == "INCLUDE" for child in declarations)):
            return data
        raise ValueError("The CodeBrowser template already defines a different BinaryRat package")
    package = ET.Element("PACKAGE", {"NAME": _PACKAGE})
    package.tail = "\n        "
    package.text = "\n            "
    package.append(ET.Comment(" Modified by YurilLAB: add the BinaryRat workspace plugins. "))
    package[0].tail = "\n            "
    for plugin in _PLUGINS:
        include = ET.SubElement(package, "INCLUDE", {"CLASS": plugin})
        include.tail = "\n            "
    package[-1].tail = "\n        "
    # Packages are parsed by name. Place our addition beside the core package.
    tool.insert(list(tool).index(core) + 1, package)
    return ET.tostring(root, encoding="utf-8", xml_declaration=True) + b"\n"


def edit_workspace_jar(data: bytes) -> bytes:
    """Rewrite one unsigned resource in Ghidra's configuration module."""
    if len(data) > _MAX_JAR_BYTES:
        raise ValueError("Unexpectedly large Ghidra configuration JAR")
    output = BytesIO()
    with ZipFile(BytesIO(data)) as source, ZipFile(output, "w") as result:
        names = source.namelist()
        if len(names) != len(set(names)) or names.count(_WORKSPACE) != 1:
            raise ValueError("Expected one CodeBrowser template in the configuration JAR")
        if (source.getinfo(_WORKSPACE).file_size > _MAX_TEMPLATE_BYTES or
                sum(entry.file_size for entry in source.infolist()) > _MAX_JAR_BYTES):
            raise ValueError("Unexpectedly large Ghidra configuration resources")
        if any(name.upper().startswith("META-INF/") and
               name.upper().endswith((".SF", ".RSA", ".DSA", ".EC")) for name in names):
            raise ValueError("Cannot edit the default workspace in a signed configuration JAR")
        result.comment = source.comment
        for entry in source.infolist():
            content = source.read(entry)
            if entry.filename == _WORKSPACE:
                content = edit_workspace(content)
            result.writestr(entry, content)
    return output.getvalue()
