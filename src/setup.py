import setuptools
import os

version = os.environ.get("AMAROQ_VERSION")

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="amaroq",
    version=version,
    author="Puma Security",
    author_email="support@pumasecurity.io",
    description="Puma Security's Amaroq Engine is a vulnerability aggregation and correlation engine for network and product security tools.",
    entry_points={"console_scripts": ["amaroq=amaroq.cli:main"]},
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/pumasecurity/amaroq",
    packages=["amaroq"],
    include_package_data=True,
    install_requires=['pyyaml','jsonschema'],
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Security",
        "Topic :: Utilities",
        "Topic :: Security",
        "Programming Language :: Python :: 3.10",
        "License :: OSI Approved :: Mozilla Public License Version 2.0",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.10",
)
