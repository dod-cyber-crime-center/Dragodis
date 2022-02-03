"""
Runs tests and other routines.

Usage:
  1. Install "nox"
  2. Run "nox" or "nox -s test"
"""
import shutil
import os
import nox


@nox.session(python="3.8")
def test(session):
    """Run pytests"""
    session.install("-e", ".[testing]")
    session.run("pytest")


@nox.session(python="3.8")
def build(session):
    """Build source and wheel distribution"""
    session.run("python", "setup.py", "sdist")
    session.run("python", "setup.py", "bdist_wheel")


@nox.session
def doc(session):
    """Builds Sphinx documentation"""
    session.run("mkdir", "-p", "dist", external=True)
    shutil.rmtree("docs/_build", ignore_errors=True)
    shutil.rmtree("dist/docs", ignore_errors=True)
    session.install("sphinx")
    session.install("sphinx-rtd-theme")
    session.install("-e", ".")

    # Autodoc
    shutil.rmtree("docs/api")
    session.run("sphinx-apidoc", "-o", "docs/api", "dragodis/interface", "--separate")

    # Build html site
    session.run("sphinx-build", "docs", "docs/_build/html", "-b", "html")
    shutil.copytree("docs/_build/html", f"dist/docs")


@nox.session(python=False)
def release_patch(session):
    """Generate release patch"""
    session.run("mkdir", "-p", "dist", external=True)
    with open("./dist/updates.patch", "w") as out:
        session.run(
            "git", "format-patch", "--stdout", "master",
            external=True,
            stdout=out
        )
