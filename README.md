# Python Sensitive File And Directory Scanner

Async Website Audit Scanner

An asynchronous website audit scanner that probes a target site for commonly exposed files and directories and produces a timestamped PDF report. It is designed for fast, configurable reconnaissance and lightweight triage of potentially sensitive content.

# Key features
Configurable list of paths to probe via paths_to_scan.py

- Fetches the homepage and inspects linked JavaScript files while skipping well-known CDN hosts to reduce noise
- Records HTTP status and content indicators for every probe and compiles a color-coded, traceable log
- Generates a timestamped PDF report containing a summary, detailed findings, and full scan log
- Risk grading using simple heuristics with optional AI-assisted triage for medium confidence results

Adjustable pacing with --speed to control per-request delay and concurrency

# How it works
The scanner reads the list of paths from paths_to_scan.py.

It requests each path and also fetches the homepage to discover linked JavaScript files. Known CDN hosts are excluded from JS fetching.

Each HTTP response is analyzed for status codes and content indicators. Matches for sensitive keywords are flagged and assigned a heuristic risk level of low, medium, or high.

When a heuristic returns medium risk, the tool can call an OpenAI model to provide a short, focused assessment on a context-limited excerpt. The AI acts as a reviewer and returns a brief explanation and a confidence estimate.

All findings are saved to a timestamped PDF report that includes a summary, detailed results, and a full color-coded log for traceability.

# Risk grading

Heuristics scan content for keywords that commonly indicate exposed secrets or credentials and assign low, medium, or high risk.

Optional AI triage: when heuristics result is medium risk, the app can send a limited excerpt to an OpenAI model that returns a short assessment and confidence. The AI is a reviewer only and not a final arbiter.

Pacing and concurrency (--speed)

slow

Strictly sequential requests

Randomized delay of about 2.0 to 4.0 seconds added immediately before each request

medium

Up to 5 concurrent requests

Jittered delay per request of roughly 0.3 to 0.75 seconds

fast

Up to 20 concurrent requests

No added delay
Concurrency is enforced with an internal asyncio semaphore and an aiohttp connector. Jitter is applied right before each fetch, so configured limits are reliably honored.

# Requirements

Python 3.9 or newer

An OpenAI API key, if you want, optional AI triage

# Installation

Clone the repository.

Create and activate a virtual environment:

python -m venv venv
source venv/bin/activate   # on Windows use: venv\Scripts\activate

# Install dependencies:

pip install -r requirements.txt

Create a .env file in the project root with your OpenAI key if using AI triage:

.env example: OPENAI_API_KEY="KEY_HERE"

To run: python app.py --speed slow

