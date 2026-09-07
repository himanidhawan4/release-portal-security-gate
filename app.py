from flask import Flask, render_template, request
import subprocess
import sys
import json
import re

app = Flask(__name__)


# ============================================================
# RUN SECURITY GATE
# ============================================================


def run_security_gate(pr_url):

    try:

        process = subprocess.run(
            [sys.executable, "-m", "src.main", pr_url],
            input="n\nn\n",
            text=True,
            capture_output=True,
            cwd="C:\\Projects\\release-portal-security-gate",
        )

        output = process.stdout

        # ----------------------------------------------------
        # If Python program failed
        # ----------------------------------------------------

        if process.returncode != 0:

            return {
                "error": "Security gate failed.",
                "details": process.stderr or output,
            }

        # ----------------------------------------------------
        # Find "Final JSON Result"
        # ----------------------------------------------------

        marker = "Final JSON Result"

        if marker not in output:

            return {"error": "Final JSON Result was not found.", "details": output}

        json_part = output.split(marker, 1)[1]

        # ----------------------------------------------------
        # Find first {
        # ----------------------------------------------------

        start = json_part.find("{")

        if start == -1:

            return {"error": "JSON result could not be found.", "details": output}

        json_part = json_part[start:]

        # ----------------------------------------------------
        # Find matching JSON object
        # ----------------------------------------------------

        decoder = json.JSONDecoder()

        try:

            result, _ = decoder.raw_decode(json_part)

        except json.JSONDecodeError as e:

            return {"error": f"Could not parse JSON result: {e}", "details": output}

        return result

    except Exception as e:

        return {"error": str(e)}


# ============================================================
# HOME PAGE
# ============================================================


@app.route("/", methods=["GET", "POST"])
def index():

    result = None
    error = None

    if request.method == "POST":

        pr_url = request.form.get("pr_url", "").strip()

        # ----------------------------------------------------
        # Validate URL
        # ----------------------------------------------------

        if not pr_url:

            error = "Please enter a GitHub Pull Request URL."

        elif not re.match(r"^https://github\.com/[^/]+/[^/]+/pull/\d+/?$", pr_url):

            error = "Please enter a valid GitHub Pull Request URL."

        else:

            result = run_security_gate(pr_url)

            # ------------------------------------------------
            # Check if scanner returned an error
            # ------------------------------------------------

            if "error" in result:

                error = result["error"]

    return render_template("index.html", result=result, error=error)


# ============================================================
# START FLASK
# ============================================================

if __name__ == "__main__":

    app.run(debug=True, host="127.0.0.1", port=5000)
