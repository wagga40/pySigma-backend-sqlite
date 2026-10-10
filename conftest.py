"""Make this checkout's backend importable under pySigma 2.0.0 editable installs.

pySigma 2.0.0 ships ``sigma/__init__.py``, so ``sigma`` stops being a namespace
package and hides ``sigma/backends/sqlite`` in this working tree. The scripts in
``tools/`` import it too. Remove this file and those imports once the dependency
floor is pysigma>=2.0.1 (SigmaHQ/pySigma#588).
"""

from pathlib import Path

import sigma

if getattr(sigma, "__file__", None):
    local = str(Path(__file__).parent / "sigma")
    if local not in sigma.__path__:
        sigma.__path__.append(local)
