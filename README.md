# Python Sensitive File And Directory Scanner

⚠️ Important Legal & Safety Notice
This tool is designed for educational and authorized security testing purposes only. Use it only against websites, servers, or environments that you own or have explicit written permission to test. Unauthorized use against third-party systems may violate laws or terms of service.

The author assumes no responsibility or liability for misuse, damage, or any consequences arising from improper or illegal use of this software. Always operate in accordance with ethical hacking principles and applicable regulations.

# Key features
Configurable list of paths to probe via paths_to_scan.py

- Fetches the homepage and inspects linked JavaScript files while skipping well-known CDN hosts to reduce noise
- Records HTTP status and content indicators for every probe and compiles a color-coded, traceable log
- Generates a timestamped PDF report containing a summary, detailed findings, and full scan log
- Risk grading using simple heuristics with optional AI-assisted triage for medium confidence results
- Soft 404 detection

Adjustable pacing with --speed to control per-request delay and concurrency

# How it works
The scanner reads its list of paths from paths_to_scan.py, then works through them one by one. It also grabs the homepage and checks any JavaScript files it finds there, ignoring anything that comes from common CDN domains.

For every HTTP response, it records the status code and looks for patterns or keywords that might indicate a security issue. Anything it flags is given a rough risk rating of low, medium, or high.

If something lands in the medium range, the scanner can optionally send a small snippet of the response to an OpenAI model. The model gives a quick opinion on whether the content looks risky, along with a short explanation and a confidence level.

All results are written to a timestamped PDF that includes a summary, the detailed findings, and a color coded log.

During the scan, the tool also generates a URL that will always return a 404. It uses this stored response as a baseline to help spot soft 404s, where a server returns a normal 200 status even though the page is basically missing.

# Risk grading

Heuristics scan the content for keywords that often point to exposed secrets or credentials and assign a risk level of low, medium, or high.

For medium-risk results, the tool can optionally run an AI triage step. It sends a small excerpt to an OpenAI model, which provides a brief assessment and a confidence rating. The AI acts only as a reviewer, not the final decision maker.

Pacing and concurrency are controlled with the --speed option.

**slow (default)**

Strictly sequential requests

Randomized delay of about 2.0 to 4.0 seconds added immediately before each request

**medium**

Up to 5 concurrent requests

Jittered delay per request of roughly 0.3 to 0.75 seconds

**fast**

Up to 20 concurrent requests

No added delay
Concurrency is enforced with an internal asyncio semaphore and an aiohttp connector. Jitter is applied right before each fetch, so configured limits are reliably honored.

# Requirements

Python 3.9 or newer

An OpenAI API key, if you want, optional AI triage

# Installation

Clone the repository.

If you want to include your logo in the report, create a directory called **images** in the root of the project and add your logo named **logo.png inside the /images directory**.

Create and activate a virtual environment:

```python -m venv venv```

``` Linux/Mac: source venv/bin/activate```

``` On Windows use: venv\Scripts\activate```

# Install dependencies:

```pip install -r requirements.txt```

Create a .env file in the project root with your OpenAI key if using AI triage:

.env example: ```OPENAI_API_KEY="KEY_HERE"```

``` To run with ai: python app.py --speed slow```

``` Run without AI: python app.py --speed fast --disable-ai ```

