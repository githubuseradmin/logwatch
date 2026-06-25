"""logwatch - a zero-dependency log analysis & security reporting CLI.

logwatch parses web access logs (NGINX/Apache combined format) and Linux
``sshd`` authentication logs and produces a clear, sectioned security/ops
report. It is built entirely on the Python standard library so it can be
dropped onto any box with Python 3.10+ and run without installing anything.

Public surface (kept small and stable):

* :func:`logwatch.cli.main`            - command line entry point
* :mod:`logwatch.parsers`              - line parsers for each log format
* :mod:`logwatch.detectors`            - security heuristics / detections (incl. allow-list)
* :mod:`logwatch.report`               - human-readable terminal report rendering
* :mod:`logwatch.exporters`            - standalone HTML / Markdown report export

Run it with::

    python -m logwatch samples/access.log
    python -m logwatch --format auth samples/auth.log
"""

__all__ = ["__version__"]

__version__ = "1.1.0"
