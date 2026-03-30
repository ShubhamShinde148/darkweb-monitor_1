from flask import Flask, request

app = Flask(__name__)

@app.route("/check")
def check():
    return {"status": "Monitoring active ✅"}

@app.route("/scan", methods=["GET"])
def scan():
    email = request.args.get("email")
    return f"Scanning for {email} 🔍"

@app.route("/")
def home():
    return """
    <h1>🚀 DarkWeb Monitor</h1>
    <form action="/scan">
        <input name="email" placeholder="Enter email">
        <button type="submit">Scan</button>
    </form>
    """
