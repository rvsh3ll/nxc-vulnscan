import sys
from importlib.util import module_from_spec, spec_from_file_location
from os.path import dirname, join

import nxc
from nxc.helpers.misc import CATEGORY
from nxc.logger import NXCAdapter

_NOT_A_HIT = (
    "found nothing",
    "not vulnerable",
    "probably patched",
    "attack failed",
    "no highlight",
)

# Stock NetExec SMB modules that CHECK a vuln or insecure config.
# Exploit/dump/exec modules are not listed. coerce_plus is called with no LISTENER
# so it only reports coerce surface (PetitPotam, PrinterBug, DFSCoerce, ShadowCoerce, MS-EVEN).
# petitpotam/printerbug/dfscoerce/shadowcoerce themselves are [REMOVED] stubs.
CHECKS = [
    # unauthenticated / authenticated on_login
    {"name": "ms17-010", "admin": False, "options": {}},
    {"name": "smbghost", "admin": False, "options": {}},
    {"name": "zerologon", "admin": False, "options": {}},
    {"name": "ntlm_reflection", "admin": False, "options": {}},
    {"name": "remove-mic", "admin": False, "options": {}},
    {"name": "printnightmare", "admin": False, "options": {}},
    {"name": "spooler", "admin": False, "options": {}},
    {"name": "webdav", "admin": False, "options": {}},
    {"name": "coerce_plus", "admin": False, "options": {}},
    {"name": "nopac", "admin": False, "options": {}},
    {"name": "enum_av", "admin": False, "options": {}},
    {"name": "enum_ca", "admin": False, "options": {}},
    {"name": "sccm-recon6", "admin": False, "options": {}},
    {"name": "ioxidresolver", "admin": False, "options": {}},
    # admin / RemoteRegistry
    {"name": "ntlmv1", "admin": True, "options": {}},
    {"name": "runasppl", "admin": True, "options": {}},
    {"name": "uac", "admin": True, "options": {}},
    {"name": "install_elevated", "admin": True, "options": {}},
    {"name": "bitlocker", "admin": True, "options": {}},
    {"name": "wdigest", "admin": True, "options": {"ACTION": "check"}},
    {"name": "wcc", "admin": True, "options": {}},
    {"name": "presence", "admin": True, "options": {}},
]


class CaptureLog:
    """Proxy NXCAdapter and keep highlight/success lines for the summary."""

    def __init__(self, inner, check_name, findings):
        self._inner = inner
        self._check = check_name
        self._findings = findings

    def highlight(self, msg, *args, **kwargs):
        self._record(str(msg))
        return self._inner.highlight(msg, *args, **kwargs)

    def success(self, msg, *args, **kwargs):
        self._record(str(msg))
        return self._inner.success(msg, *args, **kwargs)

    def _record(self, msg):
        kind = "info" if any(x in msg.lower() for x in _NOT_A_HIT) or not msg.strip() else "hit"
        self._findings.append((self._check, kind, msg))

    def fail(self, msg, *args, **kwargs):
        self._findings.append((self._check, "fail", str(msg)))
        return self._inner.fail(msg, *args, **kwargs)

    def __getattr__(self, name):
        return getattr(self._inner, name)


class WrapContext:
    def __init__(self, ctx, log):
        self._ctx = ctx
        self.log = log

    def __getattr__(self, name):
        return getattr(self._ctx, name)


def _stock_path(name):
    return join(dirname(nxc.__file__), "modules", f"{name}.py")


def _load_stock(name):
    path = _stock_path(name)
    modname = f"nxc_vulnscan_{name.replace('-', '_')}"
    spec = spec_from_file_location(modname, path)
    mod = module_from_spec(spec)
    sys.modules[modname] = mod
    spec.loader.exec_module(mod)
    return mod.NXCModule()


class NXCModule:
    """
    Run every stock NetExec Windows vulnerability *check* module in one pass.
    Check-only: never sets LISTENER, never passes enable/disable ACTION except wdigest=check.
    Module by rvsh3ll
    """

    name = "vulnscan"
    description = "Run all stock NetExec Windows vuln-check modules (no exploit). Like coerce_plus, for every check module."
    supported_protocols = ["smb"]
    category = CATEGORY.ENUMERATION

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options
        self.wanted = None
        self.skip = set()

    def options(self, context, module_options):
        """
        CHECKS    Comma-separated stock module names to run (default: all)
        SKIP      Comma-separated stock module names to skip
        LIST      If set, only print the check list and exit this host

        Never pass LISTENER. coerce_plus is invoked without a listener (check only).
        wdigest is invoked with ACTION=check only.
        """
        self.wanted = None
        self.skip = set()
        self.list_only = False
        if "CHECKS" in module_options:
            self.wanted = {x.strip().lower() for x in module_options["CHECKS"].split(",") if x.strip()}
        if "SKIP" in module_options:
            self.skip = {x.strip().lower() for x in module_options["SKIP"].split(",") if x.strip()}
        if "LIST" in module_options:
            self.list_only = True
        if "LISTENER" in module_options or "L" in module_options:
            context.log.fail("LISTENER ignored: vulnscan is check-only")

    def _selected(self, admin_privs):
        out = []
        for item in CHECKS:
            name = item["name"]
            if self.wanted is not None and name.lower() not in self.wanted:
                continue
            if name.lower() in self.skip:
                continue
            if item["admin"] and not admin_privs:
                continue
            out.append(item)
        return out

    def on_login(self, context, connection):
        self.context = context
        if self.list_only:
            for item in CHECKS:
                need = "admin" if item["admin"] else "login"
                context.log.highlight(f"{item['name']:<18} {need}")
            return

        selected = self._selected(bool(getattr(connection, "admin_privs", False)))
        if not selected:
            context.log.fail("No checks selected (need admin for admin-only modules, or CHECKS filtered everything)")
            return

        findings = []
        context.log.display(f"Running {len(selected)} stock check modules (no exploit)")

        for item in selected:
            name = item["name"]
            context.log.display(f"--- {name} ---")
            try:
                inst = _load_stock(name)
            except Exception as e:
                context.log.fail(f"{name}: failed to load ({e})")
                findings.append((name, "error", f"load: {e}"))
                continue

            extra = {
                "module_name": name.upper(),
                "host": connection.host,
                "port": connection.port,
                "hostname": connection.hostname,
            }
            sublog = CaptureLog(NXCAdapter(extra=extra), name, findings)
            subctx = WrapContext(context, sublog)
            subctx.localip = getattr(context, "localip", None)

            try:
                inst.options(subctx, dict(item.get("options") or {}))
            except SystemExit:
                context.log.fail(f"{name}: options() exited (missing required option)")
                findings.append((name, "error", "options exit"))
                continue
            except Exception as e:
                context.log.fail(f"{name}: options() error: {e}")
                findings.append((name, "error", str(e)))
                continue

            try:
                if hasattr(inst, "on_login") and callable(inst.on_login):
                    inst.on_login(subctx, connection)
                if getattr(connection, "admin_privs", False) and hasattr(inst, "on_admin_login") and callable(inst.on_admin_login):
                    inst.on_admin_login(subctx, connection)
            except SystemExit:
                context.log.fail(f"{name}: aborted (sys.exit)")
                findings.append((name, "error", "sys.exit"))
            except Exception as e:
                context.log.fail(f"{name}: {e}")
                findings.append((name, "error", str(e)))

        self._summary(context, selected, findings)

    def _summary(self, context, selected, findings):
        context.log.highlight("======== vulnscan summary ========")
        hits_by = {}
        other_by = {}
        for name, kind, msg in findings:
            if kind == "hit":
                hits_by.setdefault(name, []).append(msg)
            else:
                other_by.setdefault(name, []).append(f"{kind}: {msg}")

        for item in selected:
            name = item["name"]
            if name in hits_by:
                joined = " | ".join(hits_by[name][:4])
                context.log.highlight(f"[HIT]  {name:<18} {joined}")
            elif name in other_by:
                joined = " | ".join(other_by[name][:2])
                context.log.display(f"[info] {name:<18} {joined}")
            else:
                context.log.display(f"[----] {name:<18} no highlight (not vulnerable / no signal)")
        context.log.highlight("=================================")
