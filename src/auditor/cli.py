"""Command-line interface: argument parsing and the top-level orchestration."""

import argparse
import os
import re
import sys

from . import TOOL_NAME, __version__
from . import osv, packagejson, report, requirements
from .errors import AuditorError, NetworkError, UsageError
from .models import InputFile
from .naming import ECOSYSTEM_NPM, ECOSYSTEM_PYPI
from .severity import FAIL_ON_LEVELS

_REQUIREMENTS_BASENAME = re.compile(r"^requirements.*\.txt$")
_PACKAGE_JSON_BASENAME = "package.json"
_DIRECTORY_MANIFESTS = ("requirements.txt", "package.json")


def build_parser():
    parser = argparse.ArgumentParser(
        prog="app",
        description=(
            "Audita dependências fixadas (requirements.txt, package.json) contra o OSV.dev."
        ),
    )
    parser.add_argument(
        "path",
        nargs="?",
        metavar="PATH",
        help="arquivo de manifest ou diretório que os contenha",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="emite o relatório JSON no stdout",
    )
    parser.add_argument(
        "--fail-on",
        choices=FAIL_ON_LEVELS,
        default="high",
        metavar="LEVEL",
        help="limiar de falha: low, medium, high ou critical (padrão: high)",
    )
    parser.add_argument(
        "--version",
        action="version",
        version="%s %s" % (TOOL_NAME, __version__),
        help="imprime a versão e sai",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="suprime a saída humana; os exit codes continuam valendo",
    )
    return parser


def detect_ecosystem(path):
    """Detect the ecosystem from the file basename (SPEC §4.4)."""
    basename = os.path.basename(path)
    if _REQUIREMENTS_BASENAME.match(basename):
        return ECOSYSTEM_PYPI
    if basename == _PACKAGE_JSON_BASENAME:
        return ECOSYSTEM_NPM
    raise UsageError("formato de arquivo não reconhecido: %s" % basename)


def resolve_input_files(path):
    """Expand ``PATH`` into the list of manifest files to process."""
    if os.path.isdir(path):
        found = [
            os.path.join(path, name)
            for name in _DIRECTORY_MANIFESTS
            if os.path.isfile(os.path.join(path, name))
        ]
        if not found:
            raise UsageError("nenhum manifest (%s) encontrado em %s" % (
                ", ".join(_DIRECTORY_MANIFESTS),
                path,
            ))
        return found
    if os.path.isfile(path):
        return [path]
    raise UsageError("caminho inexistente ou inválido: %s" % path)


def _parse_file(path, ecosystem):
    if ecosystem == ECOSYSTEM_PYPI:
        return requirements.parse(path)
    return packagejson.parse(path)


def run(args):
    """Execute the audit and return the report dict."""
    # The fixture (if any) is read exactly once, before anything else.
    source = osv.build_source()

    inputs = []
    dependencies = []
    warnings = []
    for path in resolve_input_files(args.path):
        ecosystem = detect_ecosystem(path)
        file_dependencies, file_warnings = _parse_file(path, ecosystem)
        dependencies.extend(file_dependencies)
        warnings.extend(file_warnings)
        inputs.append(
            InputFile(path=path, ecosystem=ecosystem, packages_total=len(file_dependencies))
        )

    triples = [dependency.triple for dependency in dependencies if dependency.audited]
    vulnerability_map = source.query(triples)

    packages = [
        report.build_package(dependency, vulnerability_map.get(dependency.triple, []))
        for dependency in dependencies
    ]
    exit_code = report.compute_exit_code(args.fail_on, packages)
    return report.build_report(args.fail_on, inputs, packages, warnings, exit_code)


def _configure_streams():
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(encoding="utf-8")
            except (ValueError, OSError):
                pass


def main(argv=None):
    _configure_streams()
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.path is None:
        parser.error("informe exatamente um PATH")
    try:
        report_object = run(args)
    except NetworkError as error:
        print("erro: %s" % error, file=sys.stderr)
        return 3
    except AuditorError as error:
        print("erro: %s" % error, file=sys.stderr)
        return error.exit_code
    except BrokenPipeError:
        return 0
    except Exception as error:  # noqa: BLE001 - last-resort guard, exit 4
        print("erro interno: %s" % error, file=sys.stderr)
        return 4
    report.write_report(report_object, args.json, args.quiet)
    return report_object["summary"]["exit_code"]
