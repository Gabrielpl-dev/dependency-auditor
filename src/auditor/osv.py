"""Vulnerability lookup against OSV.dev, online or fixture-backed (SPEC §4)."""

import json
import os
import urllib.error
import urllib.parse
import urllib.request

from .errors import NetworkError, UsageError

FIXTURE_ENV = "AUDITOR_OSV_FIXTURE"
OSV_QUERYBATCH_URL = "https://api.osv.dev/v1/querybatch"
TIMEOUT_SECONDS = 30


def fixture_path_from_env(environ=None):
    """Return the configured fixture path, or ``None`` for online mode."""
    environ = os.environ if environ is None else environ
    value = environ.get(FIXTURE_ENV)
    if value is None or value == "":
        return None
    return value


class FixtureSource:
    """Deterministic, network-free source backed by a JSON file.

    The file is read exactly once, at construction time. Any key that is absent
    means "no known vulnerabilities" — never an error, never a network call.
    """

    def __init__(self, path):
        try:
            with open(path, "rb") as handle:
                raw = handle.read()
        except OSError as error:
            raise UsageError("não foi possível ler a fixture %s: %s" % (path, error)) from error
        try:
            data = json.loads(raw.decode("utf-8-sig"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise UsageError("fixture inválida %s: %s" % (path, error)) from error
        if not isinstance(data, dict):
            raise UsageError("fixture inválida %s: esperado um objeto JSON" % (path,))
        self._data = data

    @staticmethod
    def _key(triple):
        ecosystem, name, version = triple
        return "%s:%s@%s" % (ecosystem, name, version)

    def query(self, triples):
        results = {}
        for triple in triples:
            key = self._key(triple)
            # Extra keys are ignored; a present key must map to an array.
            if key not in self._data:
                results[triple] = []
                continue
            entry = self._data[key]
            if not isinstance(entry, list):
                raise UsageError('fixture inválida: a chave "%s" deve conter um array' % key)
            results[triple] = entry
        return results


class OnlineSource:
    """Production source: batched lookup followed by full vulnerability records."""

    def __init__(self, url=OSV_QUERYBATCH_URL, timeout=TIMEOUT_SECONDS):
        self._url = url
        self._timeout = timeout

    def query(self, triples):
        ordered = sorted(set(triples))
        if not ordered:
            return {}
        payload = {
            "queries": [
                {"package": {"name": name, "ecosystem": ecosystem}, "version": version}
                for ecosystem, name, version in ordered
            ]
        }
        body = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            self._url, data=body, headers={"Content-Type": "application/json"}, method="POST"
        )
        data = self._request_json(request)
        if not isinstance(data, dict) or not isinstance(data.get("results"), list):
            raise NetworkError("payload inesperado do OSV.dev: campo 'results' ausente")

        results = data["results"]
        if len(results) != len(ordered):
            raise NetworkError(
                "payload inesperado do OSV.dev: %d resultados para %d consultas"
                % (len(results), len(ordered))
            )

        mapping = {}
        records = {}
        for triple, result in zip(ordered, results):
            if not isinstance(result, dict):
                raise NetworkError("payload inesperado do OSV.dev: resultado não é um objeto")
            vulns = result.get("vulns", [])
            if vulns is None:
                vulns = []
            if not isinstance(vulns, list):
                raise NetworkError("payload inesperado do OSV.dev: campo 'vulns' inválido")
            full_vulns = []
            for vulnerability in vulns:
                identifier = vulnerability.get("id") if isinstance(vulnerability, dict) else None
                if not isinstance(identifier, str) or not identifier:
                    raise NetworkError("payload inesperado do OSV.dev: id inválido")
                if identifier not in records:
                    url = self._url.rsplit("/", 1)[0] + "/vulns/" + urllib.parse.quote(identifier, safe="")
                    record = self._request_json(urllib.request.Request(url, method="GET"))
                    if not isinstance(record, dict) or record.get("id") != identifier:
                        raise NetworkError("payload inesperado do OSV.dev: registro inválido")
                    records[identifier] = record
                full_vulns.append(records[identifier])
            mapping[triple] = full_vulns
        return mapping


    def _request_json(self, request):
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as response:
                status = getattr(response, "status", 200)
                raw = response.read()
        except urllib.error.HTTPError as error:
            raise NetworkError("OSV.dev respondeu HTTP %s" % (error.code,)) from error
        except (urllib.error.URLError, OSError, TimeoutError) as error:
            raise NetworkError("falha de rede ao consultar o OSV.dev: %s" % (error,)) from error

        if not 200 <= status < 300:
            raise NetworkError("OSV.dev respondeu HTTP %s" % (status,))
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise NetworkError("payload inesperado do OSV.dev: %s" % (error,)) from error
        return data


def build_source(environ=None):
    """Pick the source according to ``AUDITOR_OSV_FIXTURE``."""
    path = fixture_path_from_env(environ)
    if path is None:
        return OnlineSource()
    return FixtureSource(path)
