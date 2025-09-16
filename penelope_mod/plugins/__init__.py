import pkgutil
import importlib
import inspect
from .base import Module


def discover():
    modules = {}
    pkg_name = __name__  # 'penelope_mod.plugins'
    # Iterate over all submodules in this package
    for finder, name, ispkg in pkgutil.iter_modules(__path__):  # type: ignore[name-defined]
        if name.startswith("_") or name in ("base",):
            continue
        full_name = f"{pkg_name}.{name}"
        try:
            mod = importlib.import_module(full_name)
        except Exception as e:
            try:
                from penelope_mod.context import ctx
                if ctx and ctx.logger:
                    ctx.logger.error(f"Failed to load plugin {full_name}: {e}")
            except Exception:
                pass
            continue
        # Collect Module subclasses defined in this module
        for attr_name, obj in vars(mod).items():
            if inspect.isclass(obj) and issubclass(obj, Module) and obj is not Module:
                modules[obj.__name__] = obj
    return modules

