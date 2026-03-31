================================================================================
  AXIOS SUPPLY CHAIN ATTACK — DETECTION & FIX SCRIPTS
================================================================================

I work on a lot of Node.js projects and when I heard about the Axios supply
chain attack I needed a way to check all of my projects and my
whole machine for any signs of compromise. Going through each project one by
one wasn't realistic, so I put together these scripts to do the heavy lifting
for me scan everything, flag anything bad, and fix it on the spot.

Feel free to use it, share it, or adapt it however you need.


NEWS Links
----------
  - https://www.malwarebytes.com/blog/news/2026/03/axios-supply-chain-attack-chops-away-at-npm-trust
  - sans.org/blog/axios-npm-supply-chain-compromise-malicious-packages-remote-access-trojan


THE ISSUE
---------

Axios is a promise-based HTTP client for Node.js — a helper tool that
developers use behind the scenes to let apps talk to the internet. It makes
requests like "get my messages from the server" or "send this form to the
website" easier and more reliable, saving programmers from writing a lot of
low-level networking code themselves.

Because it works both in the browser and on servers (Node.js), a huge number of
modern JavaScript-based projects include it as a standard building block. Even
if you never install Axios yourself, you might indirectly depend on it when you:

  - Use web apps built with frameworks like React, Vue, or Angular.
  - Use mobile or desktop apps built with web technologies like Electron,
    React Native, and others.
  - Visit smaller SaaS tools, admin panels, or self-hosted services built by
    developers who chose Axios.

Using compromised credentials of a lead Axios maintainer, an attacker published
poisoned packages to npm:

  - axios@1.14.1
  - axios@0.30.4

The malicious versions inject a new dependency — plain-crypto-js@4.2.1 — which
is never imported anywhere in the legitimate Axios source code.

Together the two affected packages reach up to 100 million weekly downloads on
npm, giving this attack a massive impact radius across web apps, services, and
CI/CD pipelines.

Importantly, the affected Axios versions do NOT appear in the project's official
GitHub tags. The people and projects affected are developers and environments
that ran "npm install" and resolved to:

  - axios@1.14.1 or axios@0.30.4, or
  - the dependency plain-crypto-js@4.2.1

Any workflow that installed one of those versions with scripts enabled may have
exposed all injected secrets (cloud keys, repo deploy keys, npm tokens, etc.)
to an interactive attacker, because the postinstall script ("node setup.js")
that runs automatically on npm install downloaded an obfuscated dropper that
retrieves a platform-specific RAT (Remote Access Trojan) payload for macOS,
Windows, or Linux.


================================================================================


WHAT THESE SCRIPTS DO
---------------------

Two scripts are provided — one for each platform:

  - check_and_fix.ps1   (PowerShell, for Windows)
  - check_and_fix.sh    (Bash, for macOS and Linux)

Both scripts detect and automatically fix projects affected by the Axios supply
chain attack. They can run against a single project or scan every Node.js
project under a given folder.

By default, when a compromised project is found the scripts will:

  - Pin the axios version in package.json to the latest safe release (queried
    from npm at runtime, falling back to 1.14.0 if npm is unavailable).
  - Delete the compromised node_modules/axios and node_modules/plain-crypto-js
    directories.
  - Remove the lockfile (package-lock.json or yarn.lock) if it contains
    references to the compromised versions, so that "npm install" will
    regenerate a clean one.

Use -CheckOnly (PowerShell) or --check-only (Bash) to scan without modifying
anything.

The scripts perform two categories of checks:


  A. Per-Project Checks (run for each discovered project)
  --------------------------------------------------------

  1. Axios Dependency Check
     Reads the project's package.json to determine if it depends on Axios at
     all. Projects that don't use Axios are skipped immediately.

  2. Installed Version Check
     Reads node_modules/axios/package.json directly (no npm call needed) to see
     if the installed version is one of the compromised releases: 1.14.1 or
     0.30.4.

  3. Lockfile Check
     Scans package-lock.json (or yarn.lock) for references to the compromised
     versions or the malicious plain-crypto-js package.

  4. Malicious Package Check
     Looks for node_modules/plain-crypto-js on disk. Note: the malware is
     designed to self-destruct after execution, so its absence does NOT
     guarantee safety.


  B. System-Wide Checks (run once regardless of how many projects are scanned)
  -----------------------------------------------------------------------------

  5. RAT Artifact Check
     Windows  — Looks for wt.exe in %PROGRAMDATA% and temporary payload files
                (6202033.vbs, 6202033.ps1) in %TEMP%.
     macOS    — Looks for /Library/Caches/com.apple.act.mond.
     Linux    — Looks for /tmp/ld.py.

  6. C2 Connection Check
     Uses netstat (or ss on Linux) to check for active network connections to
     the known command-and-control server IP address 142.11.206.73.
     The Bash script also scans /var/log/ for DNS queries to sfrclak.com.


================================================================================


USAGE — WINDOWS (PowerShell)
----------------------------

Open PowerShell and navigate to the folder containing check_and_fix.ps1, then
run one of the following:

  Scan and fix the current directory (single project):

    .\check_and_fix.ps1

  Scan and fix every Node.js project under a specific folder:

    .\check_and_fix.ps1 -Path D:\Projects

  Scan and fix an entire drive:

    .\check_and_fix.ps1 -Path C:\

  Limit how deep the folder search goes (default is 10 levels):

    .\check_and_fix.ps1 -Path D:\Projects -MaxDepth 2

  Only check — do NOT modify any files:

    .\check_and_fix.ps1 -CheckOnly

  Pin to a specific safe version instead of querying npm:

    .\check_and_fix.ps1 -SafeVersion "1.13.7"

  Skip the system-wide RAT and C2 checks (project checks only):

    .\check_and_fix.ps1 -SkipSystemChecks


USAGE — macOS / LINUX (Bash)
-----------------------------

Make the script executable, then run it from a terminal:

  chmod +x check_and_fix.sh

  Scan and fix the current directory (single project):

    ./check_and_fix.sh

  Scan and fix every Node.js project under a specific folder:

    ./check_and_fix.sh --path ~/projects

  Scan and fix an entire filesystem:

    ./check_and_fix.sh --path /

  Limit how deep the folder search goes (default is 10 levels):

    ./check_and_fix.sh --path ~/projects --max-depth 2

  Only check — do NOT modify any files:

    ./check_and_fix.sh --check-only

  Pin to a specific safe version instead of querying npm:

    ./check_and_fix.sh --safe-version "1.13.7"

  Skip the system-wide RAT and C2 checks (project checks only):

    ./check_and_fix.sh --skip-system-checks


================================================================================


PARAMETERS
----------

Both scripts accept the same parameters with platform-appropriate syntax.

  PowerShell                     Bash
  ──────────────────────────     ──────────────────────────────
  -Path <string>                 --path <string>
  -MaxDepth <int>                --max-depth <int>
  -CheckOnly                     --check-only
  -SafeVersion <string>          --safe-version <string>
  -SkipSystemChecks              --skip-system-checks

  Path / --path
      The root folder to scan recursively. When omitted, only the current
      working directory is checked as a single project.

  MaxDepth / --max-depth
      How many directory levels deep to search for package.json files.
      Default: 10.

  CheckOnly / --check-only
      When set, the script only scans and reports — it will NOT modify
      package.json, delete node_modules, or remove lockfiles.

  SafeVersion / --safe-version
      The exact axios version to pin in package.json when fixing a project.
      When omitted, the script queries npm for the latest published version.
      If that fails or returns a compromised version, it falls back to 1.14.0.

  SkipSystemChecks / --skip-system-checks
      When set, the script skips the RAT artifact and C2 connection checks
      and only performs per-project scanning.


================================================================================


OUTPUT
------

Both scripts print color-coded results to the console:

  GREEN   — Check passed, no issues found.
  RED     — Compromised indicator detected.
  CYAN    — Fix action taken (package.json updated, files removed, etc.).
  YELLOW  — Section header, informational warning, or fix-related reminder.
  GRAY    — Check was skipped (not applicable to this project).

When scanning multiple projects, a summary at the end lists:

  - Total number of projects scanned.
  - Number of affected projects.
  - Number of projects that were automatically fixed.
  - Full paths to every affected project (marked with "fixed" where applicable).


================================================================================


IF COMPROMISE IS DETECTED
-------------------------

When run without -CheckOnly / --check-only, the scripts automatically handle
steps 1–3 below. You still need to perform steps 4–7 manually.

  1. [AUTO] Pin Axios to a safe version in package.json.

  2. [AUTO] Remove the compromised node_modules/axios and
     node_modules/plain-crypto-js directories.

  3. [AUTO] Delete the lockfile if it contains compromised references.

  4. Run "npm install" in each fixed project to regenerate a clean lockfile and
     download the safe version of axios.

  5. Rotate ALL credentials — npm tokens, cloud keys, deploy keys, API secrets,
     database passwords, and anything else that was accessible in the
     environment where the compromised package was installed.

  6. Block the attacker's infrastructure:
       - Domain: sfrclak.com
       - IP:     142.11.206.73

  7. If any RAT artifact was found (wt.exe on Windows, com.apple.act.mond on
     macOS, or ld.py on Linux), treat the machine as fully compromised and
     perform a COMPLETE SYSTEM REBUILD.


================================================================================


PREVENTIVE MEASURES
-------------------

Even if you are not currently affected, consider these steps:

  - Pin your Axios version explicitly:
      npm install axios@1.14.0 --save-exact

  - Enable npm's minimum release age to avoid installing brand-new packages
    before the community has had time to review them:
      npm config set min-release-age 3

  - Use --ignore-scripts during installation in CI/CD pipelines where
    postinstall scripts are not needed, to prevent automatic execution of
    malicious code.

  - Regularly audit your dependencies:
      npm audit


================================================================================
