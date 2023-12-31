from os import path
from setuptools import setup
from setuptools import find_packages

version = "1.0.2"

install_requires = [
    'certbot>=0.31.0',
    'nitrado>=1.0.33'
]
test_requirements = [
    'mock',
    'requests'
]

# read the contents of the README file

this_directory = path.abspath(path.dirname(__file__))
with open(path.join(this_directory, "README.md")) as f:
    long_description = f.read()

setup(
    name="certbot-dns-nitrado",
    version=version,
    description="Nitrado DNS Authenticator plugin for Certbot",
    long_description=long_description,
    long_description_content_type="text/markdown",
    repository="https://github.com/CoV-Tech/certbot-dns-nitrado",
    author="Ukhando Ithunzi",
    author_email="ukhando@community-of-the-void.eu",
    python_requires=">=3.6",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Environment :: Plugins",
        "Intended Audience :: System Administrators",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Security",
        "Topic :: System :: Installation/Setup",
        "Topic :: System :: Networking",
        "Topic :: Internet :: Name Service (DNS)",
        "Topic :: System :: Systems Administration",
        "Topic :: Utilities",
    ],
    packages=find_packages(),
    install_requires=install_requires,
    tests_require=test_requirements,
    entry_points={
        "certbot.plugins": [
            "dns-nitrado = certbot_dns_nitrado.dns_nitrado:Authenticator"
        ]
    },
    test_suite="certbot_dns_nitrado",
)
