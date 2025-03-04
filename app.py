from flask import Flask, jsonify, send_from_directory
from flask_socketio import SocketIO, emit
import requests
import threading
import json
import os
from pathlib import Path
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

#socketio = SocketIO(app)
socketio = SocketIO(app, 
    cors_allowed_origins="*",  # Allow all origins
)

BASE_DIR = Path(__file__).resolve().parent


# Handle HTTP requests
@app.route("/trends/<country_code>", methods=["GET"])
def get_country_trends(country_code):
    country_code = country_code.upper() if country_code else ""
    try:
        response = requests.get(f"https://threatmap-api.checkpoint.com/ThreatMap/api/countries/{country_code}")
        return jsonify(response.json())
    except Exception as e:
        return jsonify({"error": "Failed to fetch country trends", "message": str(e)}), 500


@app.route("/getTopStats", methods=["GET"])
def get_top_stats():
    try:
        response = requests.get("https://www.imperva.com/public/threat-map-data-v2/day=2025-02-15/stats.json")
        print(response.json())
        return jsonify(response.json())
    except Exception as e:
        return jsonify({"error": "Failed to fetch topStats", "message": str(e)}), 500


# Serve static files
@app.route("/")
def serve_index():
    return send_from_directory(os.path.join(BASE_DIR, "src"), "index.html")

@app.route("/<path:filename>")
def serve_static(filename):
    return send_from_directory(os.path.join(BASE_DIR, "src"), filename)


# WebSocket function to stream threat data
def stream_threat_data():
    while True:
        try:
            response = requests.get("https://threatmap-api.checkpoint.com/ThreatMap/api/feed", stream=True)
            for chunk in response.iter_content(chunk_size=512):
                if chunk:
                    try:
                        decoded_data = chunk.decode("utf-8").strip()
                        if decoded_data.startswith("data:"):
                            decoded_data = decoded_data[5:].strip()

                        threat_data = json.loads(decoded_data)  
                        socketio.emit('threat_data', json.dumps(threat_data), namespace='/')
                    except json.JSONDecodeError:
                        continue  # Skip any chunk that cannot be parsed
        except Exception as e:
            print(f"Error fetching data from the API: {e}")


# SocketIO event for WebSocket connection
@socketio.on('connect')
def handle_connect():
    print("New WebSocket client connected")
    # Start the thread for streaming data if it's not already running
    if not any(thread.name == "stream_thread" for thread in threading.enumerate()):
        stream_thread = threading.Thread(target=stream_threat_data, name="stream_thread")
        stream_thread.daemon = True
        stream_thread.start()


@socketio.on('disconnect')
def handle_disconnect():
    print("WebSocket client disconnected")


if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=3000)
