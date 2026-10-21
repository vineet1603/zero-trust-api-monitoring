from flask import Flask, render_template, jsonify
from pymongo import MongoClient
from datetime import datetime
import random

app = Flask(__name__)

# Connect to database
client = MongoClient("mongodb://localhost:27017/")
db = client["zero_trust_engine_db"]

@app.route('/')
def dashboard():
    return render_template('dashboard.html')

@app.route('/api/stats/action-frequency')
def action_frequency():
    pipeline = [{"$group": {"_id": "$action_taken", "count": {"$sum": 1}}}]
    data = list(db.traffic_logs.aggregate(pipeline))
    return jsonify(data)

@app.route('/api/stats/average-threat')
def average_threat():
    pipeline = [
        {"$group": {"_id": "$policy_id", "avg_threat": {"$avg": "$threat_score"}}},
        {"$lookup": {"from": "security_policies", "localField": "_id", "foreignField": "_id", "as": "policy"}},
        {"$unwind": "$policy"},
        {"$project": {"_id": 0, "endpoint": "$policy.endpoint_name", "avg_threat": {"$round": ["$avg_threat", 2]}}},
        {"$sort": {"avg_threat": -1}}
    ]
    data = list(db.traffic_logs.aggregate(pipeline))
    return jsonify(data)

# NEW: Route to generate random traffic on demand
@app.route('/api/simulate-traffic', methods=['POST'])
def simulate_traffic():
    policies = list(db.security_policies.find({}, {"_id": 1}))
    if not policies:
        return jsonify({"error": "No policies found in DB"}), 400

    actions = ["ALLOWED", "BLOCKED", "FLAGGED"]
    ips = ["192.168.1.10", "10.0.0.55", "172.16.2.8", "45.22.19.11", "203.0.113.4"]
    
    new_logs = []
    # Generate 5 new random traffic logs
    for _ in range(5):
        new_logs.append({
            "policy_id": random.choice(policies)["_id"],
            "source_ip": random.choice(ips),
            "threat_score": random.randint(0, 100),
            "action_taken": random.choice(actions),
            "timestamp": datetime.now()
        })
    
    # Insert them into MongoDB
    db.traffic_logs.insert_many(new_logs)
    return jsonify({"status": "success", "message": "Added 5 new requests"})

if __name__ == '__main__':
    app.run(debug=True, port=5000)