import os
from flask import Flask, request, jsonify
from werkzeug.utils import secure_filename

# Import pipeline modules
from parser import parse_pcap
from cleaner import clean_data
from eda import run_eda
from analyzer import analyze_data
from ai_interpreter import generate_interpretation

app = Flask(__name__)

UPLOAD_FOLDER = "uploads"
ALLOWED_EXTENSIONS = {"pcap", "pcapng"}

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

os.makedirs(UPLOAD_FOLDER, exist_ok=True)


# -----------------------------------
# File validation
# -----------------------------------
def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


# -----------------------------------
# Upload + full analysis pipeline
# -----------------------------------
@app.route("/upload", methods=["POST"])
def upload_pcap():

    if "pcap_file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files["pcap_file"]

    if file.filename == "":
        return jsonify({"error": "Empty filename"}), 400

    if not allowed_file(file.filename):
        return jsonify({"error": "Invalid file type"}), 400

    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)

    file.save(filepath)

    try:
        # -----------------------------
        # Step 1 — Parse PCAP
        # -----------------------------
        packets_df = parse_pcap(filepath)

        # -----------------------------
        # Step 2 — Data Cleaning
        # -----------------------------
        cleaned_df = clean_data(packets_df)

        # -----------------------------
        # Step 3 — Exploratory Analysis
        # -----------------------------
        eda_results = run_eda(cleaned_df)

        # -----------------------------
        # Step 4 — ML / Statistical Analysis
        # -----------------------------
        analysis_results = analyze_data(cleaned_df)

        # -----------------------------
        # Step 5 — AI Interpretation
        # -----------------------------
        interpretation = generate_interpretation(
            cleaned_df,
            eda_results,
            analysis_results
        )

        return jsonify({
            "message": "Analysis complete",
            "eda": eda_results,
            "analysis": analysis_results,
            "ai_interpretation": interpretation
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# -----------------------------------
# Health check
# -----------------------------------
@app.route("/")
def home():
    return jsonify({"status": "PacketLens backend running"})


# -----------------------------------
# Run server
# -----------------------------------
if __name__ == "__main__":
    app.run(debug=True)