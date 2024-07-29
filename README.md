# FastAPI Automated Security Testing

> "Waiting to address software security vulnerabilities until it’s too late can be costly and open organizations up to unnecessary risk. This is why it’s important to develop securely from the start, which is known as shift left security."
>
> ~[Snyk, on Shift Left Security](https://snyk.io/learn/shift-left-security/)

Penetration tests and vulnerability assessments are a crucial part of assessing an application's security -- however, they're often done very late in the development process.

If a massive security bug is found when an application is staged to deploy, fixing it is a lot costlier than finding it in design or testing.

**Small Problem:** How do you validate the presence of security bugs before a pentest?

Sadly, you can't, not for everything. However, developers already have tools to catch many bugs before an app reaches production: Automated Test Suites. They're both consistent and scalable, so they're great to have as a project grows and manual testing becomes more difficult.

Why don't we try to use those to find our security bugs?

## Contents

- [Automated Security Testing Substack Series](#automated-security-testing-substack-series)
- [About This Codebase](#about-this-codebase)
  - [V1 and V2: Insecure and Secure Versions](#v1-and-v2-insecure-and-secure-versions)
  - [Active Examples](#active-examples)
- [Installation](#installation)
- [Usage](#usage)
- [Contributing](#contributing)

## Automated Security Testing Substack Series

Articles coming soon!

## About This Codebase

This is a FastAPI toy application, designed as a collection of endpoints purpose-built to showcase various security vulnerabilities. However, the principles here apply across languages, frameworks, and codebases.

The main attractions here are the test suites, which show the different security vulnerabilities and what API **integration test cases** for them might look like.

> **Integration Test Case**: A test case designed to validate that different pieces of an application are working correctly. E.g., a case that tests live API calls and database operations on a single endpoint.

|Tech Stack||
|-|-|
|**Language**|Python|
|**Framework**|FastAPI|
|**Test Libraries**|pytest, responses|
|**Database**|Currently N/A|

### V1 and V2: Insecure and Secure Versions

In the application, there are 2 API versions: `v1`, and `v2`. `v1` hosts the vulnerable versions of each endpoint. `v2`, correspondingly, hosts the secure versions of each endpoint. Each endpoint is designed to highlight one particular security flaw -- a CWE, or Common Weakness Enumeration.

### Active Examples - OWASP Top 10 2021

- [Broken Access Control](tests/test_broken_access_control.py)
  - [CWE-22 Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')](https://cwe.mitre.org/data/definitions/22.html)
  - [CWE-23 Relative Path Traversal](https://cwe.mitre.org/data/definitions/23.html)
  - [CWE-285 Improper Authorization](https://cwe.mitre.org/data/definitions/285.html)
- [Serverside Request Forgery (SSRF)](tests/test_ssrf.py)
  - [CWE-918 Server-Side Request Forgery (SSRF)](https://cwe.mitre.org/data/definitions/918.html)

## Installation

If you would like to install this project yourself, here are the (very simple) requirements:

- Python 3.10 or higher (this project has not been tested on <=3.9)
- Linux-based operating system (MacOS and Windows installation instructions should be similar, but I haven't verified this)
- Git

First, clone the repository and enter the directory:

```bash
git clone https://github.com/ApprenticeofEnder/FastAPI-automated-security-testing.git # Clone
cd FastAPI-automated-security-testing # Enter
```

Next, create a virtual environment named `env` (I'm using venv, but you can use another tool if you prefer):

```bash
python3 -m venv env
```

Finally, install the dev dependencies, which include [`pytest`](https://docs.pytest.org/en/7.1.x/contents.html) and the [`responses`](https://pypi.org/project/responses/) library:

```bash
pip install -r requirements.dev.txt
```

## Usage

To run the test suites, simply run:

```bash
pytest
```

## Contributing

Sadly, this project is not yet open for pull requests, as it is supplementary material to my Substack series -- I will make an announcement should that change!

However, should you find an issue with the code, please raise a Github Issue explaining exactly what problem you have encountered.
