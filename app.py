"""Application entry point for Q-SAFE Nexus."""

from flask import Flask, render_template, request, redirect, send_file, url_for
from werkzeug.exceptions import RequestEntityTooLarge

from config import Config, TRANSFER_FOLDER, UPLOAD_FOLDER
from services.database import init_database
from services.dashboard_service import summarize_dashboard
from services.result_store import result_store
from services.upload_service import UploadValidationError, process_uploaded_file
from services.attack_service import get_attack_logs, clear_attack_logs
from services.score_service import get_scores
from services.report_service import ReportNotFoundError, generate_security_report


def create_app() -> Flask:
    """Create and configure the Flask application."""
    app = Flask(__name__)

    # Core application configuration.
    app.config.from_object(Config)

    # Ensure the upload directory exists before handling requests.
    UPLOAD_FOLDER.mkdir(exist_ok=True)
    TRANSFER_FOLDER.mkdir(parents=True, exist_ok=True)
    init_database()

    # Public landing page.
    @app.route("/")
    def home():
        return render_template("home.html")

    # Upload interface and file intake handler.
    @app.route("/upload", methods=["GET", "POST"])
    def upload():
        uploaded_file_name = None
        encrypted_file_name = None
        error = None
        result = None

        if request.method == "POST":
            simulate_mitm = request.form.get("simulate_mitm") == "1"
            simulate_replay = request.form.get("simulate_replay") == "1"
            simulate_tampering = request.form.get("simulate_tampering") == "1"

            try:
                result = process_uploaded_file(
                    request.files.get("file"),
                    app.config["UPLOAD_FOLDER"],
                    app.config["TRANSFER_FOLDER"],
                    simulate_mitm=simulate_mitm,
                    simulate_replay=simulate_replay,
                    simulate_tampering=simulate_tampering,
                )
                uploaded_file_name = result["file_name"]
                encrypted_file_name = result["encrypted_file_name"]
            except UploadValidationError as exc:
                error = str(exc)

        return render_template(
            "upload.html",
            uploaded_file_name=uploaded_file_name,
            encrypted_file_name=encrypted_file_name,
            error=error,
            result=result,
        )

    # User-friendly response for files over the configured 10MB limit.
    @app.errorhandler(RequestEntityTooLarge)
    def handle_file_too_large(error):
        return (
            render_template(
                "upload.html",
                error="File size must be 10MB or smaller.",
                encrypted_file_name=None,
                uploaded_file_name=None,
            ),
            413,
        )

    # Operational dashboard for system status and analysis summaries.
    @app.route("/dashboard")
    def dashboard():
        results = result_store.all()
        attack_logs = get_attack_logs()
        score_history = get_scores(limit=50)
        return render_template(
            "dashboard.html",
            results=results,
            summary=summarize_dashboard(results),
            attack_logs=attack_logs,
            score_history=score_history,
        )

    @app.route("/generate-report/<transfer_id>")
    def generate_report(transfer_id: str):
        """Generate and download a PDF security report for one transfer."""
        try:
            pdf_path = generate_security_report(transfer_id)
        except ReportNotFoundError:
            return {"error": f"No data found for transfer_id {transfer_id}"}, 404

        return send_file(
            pdf_path,
            mimetype="application/pdf",
            as_attachment=True,
            download_name=pdf_path.name,
        )

    @app.route("/clear", methods=["POST"])
    def clear():
        result_store.clear()
        clear_attack_logs()
        # Also wipe security_scores so the dashboard resets cleanly.
        from services.database import get_connection
        with get_connection() as conn:
            conn.execute("DELETE FROM security_scores")
        return redirect(url_for("dashboard"))

    return app


app = create_app()


if __name__ == "__main__":
    # Local development server entry point.
    app.run(debug=True)
