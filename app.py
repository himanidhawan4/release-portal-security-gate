from flask import Flask, render_template, request
import re

from src.main import run_security_gate

app = Flask(__name__)


def is_valid_pr_url(pr_url):
    if not pr_url:
        return False

    pattern = r"^https://github\.com/[^/\s]+/[^/\s]+/pull/\d+/?$"

    return re.fullmatch(pattern, pr_url) is not None


@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    error = None
    include_details = False
    pr_url = ""

    if request.method == "GET":
        return render_template(
            "index.html",
            result=None,
            error=None,
            include_details=False,
            pr_url="",
        )

    pr_url = request.form.get("pr_url", "").strip()
    include_details = request.form.get("include_details") == "on"

    if not pr_url:
        error = "Please enter a GitHub Pull Request URL."

    elif not is_valid_pr_url(pr_url):
        error = (
            "Please enter a valid GitHub Pull Request URL. "
            "Example: https://github.com/owner/repository/pull/123"
        )

    else:
        try:
            result = run_security_gate(
                pr_url,
                include_details=include_details,
            )

            if isinstance(result, dict) and result.get("error"):
                error = result.get(
                    "error",
                    "Security gate could not complete.",
                )
                result = None

        except Exception as e:
            error = f"Security gate failed: {str(e)}"
            result = None

    return render_template(
        "index.html",
        result=result,
        error=error,
        include_details=include_details,
        pr_url=pr_url,
    )


if __name__ == "__main__":
    app.run(
        debug=False,
        host="127.0.0.1",
        port=5000,
    )
