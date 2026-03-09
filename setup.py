from setuptools import setup, find_packages

setup(
    name="agent-audit",
    version="1.0.0",
    description="Behavioral Audit Engine for Autonomous AI Agents",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="Varun Meda",
    author_email="varunmeda95@gmail.com",
    url="https://github.com/VMaroon95/agent-audit",
    packages=find_packages(),
    python_requires=">=3.10",
    entry_points={
        "console_scripts": [
            "agent-audit=cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
    ],
)
