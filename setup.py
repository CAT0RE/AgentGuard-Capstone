from setuptools import find_packages, setup


setup(
    name="agentguard-capstone",
    version="0.5.0",
    description="Runtime security monitoring for tool-using LLM agents",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    python_requires=">=3.9",
    package_dir={"": "src"},
    packages=find_packages("src"),
    package_data={"agentguard": ["static/*", "assets/*.json"]},
    data_files=[
        (
            "share/agentguard/benchmarks",
            [
                "benchmarks/cases.jsonl",
                "benchmarks/case.schema.json",
                "benchmarks/annotation.schema.json",
                "benchmarks/ANNOTATION_GUIDE.md",
            ],
        )
    ],
    include_package_data=True,
    entry_points={"console_scripts": ["agentguard=agentguard.cli:main"]},
    license="MIT",
    keywords="llm agents security prompt-injection monitoring",
)
