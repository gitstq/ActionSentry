from setuptools import setup, find_packages

setup(
    name="actionsentry",
    version="1.0.0",
    description="A lightweight GitHub Actions workflow security static analysis engine",
    long_description=open("README.md").read() if __import__("os").path.exists("README.md") else "",
    long_description_content_type="text/markdown",
    author="ActionSentry Contributors",
    license="MIT",
    python_requires=">=3.8",
    packages=find_packages(),
    install_requires=[],
    extras_require={},
    entry_points={
        "console_scripts": [
            "actionsentry=actionsentry.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
    ],
)
