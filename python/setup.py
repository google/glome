import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="pyglome",
    version="0.0.2",
    author="Google LLC",
    description="A Python implementation of GLOME protocol",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/google/glome",
    packages=["pyglome"],
    install_requires=[
        "cryptography",
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache Software License",
    ],
    python_requires='>=3.6',
)
