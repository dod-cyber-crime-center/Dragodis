import shutil
import os
import nox


@nox.session
def doc(session):
    """Builds Sphinx documentation"""
    shutil.rmtree("docs/_build", ignore_errors=True)
    shutil.rmtree("dist", ignore_errors=True)
    os.mkdir("dist")
    session.install("sphinx")
    session.install("sphinx-rtd-theme")
    session.install("-e", ".")

    # Autodoc
    shutil.rmtree("docs/api")
    session.run("sphinx-apidoc", "-o", "docs/api", "dragodis/interface", "--separate")

    # Build html site
    session.run("sphinx-build", "docs", "docs/_build/html", "-b", "html")
    shutil.copytree("docs/_build/html", f"dist/Dragodis_documentation")
