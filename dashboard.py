from flask import Flask, render_template, jsonify, request
import os, json

app = Flask(__name__)

RULES_FILE = "rules.json"
LOG_FILE = "logs/shieldpy.log"

# === Helper Functions ===
def load_rules():
    if os.path.exists(RULES_FILE):
        with open(RULES_FILE, "r") as f:
            return json.load(f)
    return {"blocked_ips": [], "allowed_ports": [], "blocked_protocols": []}

def save_rules(rules):
    with open(RULES_FILE, "w") as f:
        json.dump(rules, f, indent=4)

# === Routes ===
@app.route("/")
def index():
    return render_template("index1.html")

@app.route("/logs")
def get_logs():
    logs = []
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as f:
            lines = f.readlines()[-50:]
            logs = [line.strip() for line in lines]
    return jsonify(logs)

@app.route("/stats")
def stats():
    blocked = allowed = 0
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as f:
            for line in f:
                if "Blocked" in line:
                    blocked += 1
                elif "Allowed" in line:
                    allowed += 1
    return jsonify({"blocked": blocked, "allowed": allowed})

# === Rule Management ===
@app.route("/rules")
def get_rules():
    return jsonify(load_rules())

@app.route("/add_rule", methods=["POST"])
def add_rule():
    rules = load_rules()
    data = request.json
    category = data.get("category")
    value = data.get("value")

    if category in rules and value not in rules[category]:
        rules[category].append(value)
        save_rules(rules)
        return jsonify({"status": "success", "message": f"Added {value} to {category}"})
    return jsonify({"status": "error", "message": "Invalid rule or already exists"})

@app.route("/remove_rule", methods=["POST"])
def remove_rule():
    rules = load_rules()
    data = request.json
    category = data.get("category")
    value = data.get("value")

    if category in rules and value in rules[category]:
        rules[category].remove(value)
        save_rules(rules)
        return jsonify({"status": "success", "message": f"Removed {value} from {category}"})
    return jsonify({"status": "error", "message": "Rule not found"})

if __name__ == "__main__":
    app.run(debug=True)
