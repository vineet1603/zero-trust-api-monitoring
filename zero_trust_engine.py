from pymongo import MongoClient
from bson.objectid import ObjectId
from datetime import datetime, timedelta
import random

# Connect to local MongoDB
client = MongoClient("mongodb://localhost:27017/")
db_name = "zero_trust_engine_db"

# Reset database for clean run
client.drop_database(db_name)
db = client[db_name]

print("STEP 1: Reset & create validated collections")
print("======================================================")

# 1. Schema Validation for security_policies
policy_validator = {
    "$jsonSchema": {
        "bsonType": "object",
        "required": ["endpoint_name", "method", "max_payload_size", "auth_required"],
        "properties": {
            "endpoint_name": {"bsonType": "string"},
            "method": {"bsonType": "string", "enum": ["GET", "POST", "PUT", "DELETE"]},
            "max_payload_size": {
                "bsonType": "int",
                "minimum": 500,
                "maximum": 8000,
                "description": "must be an integer between 500 and 8000 inclusive"
            },
            "auth_required": {"bsonType": "bool"}
        }
    }
}
db.command({"create": "security_policies", "validator": policy_validator})
print("[OK] 'security_policies' collection created with schema validation.")

# 2. Schema Validation for traffic_logs
log_validator = {
    "$jsonSchema": {
        "bsonType": "object",
        "required": ["policy_id", "source_ip", "threat_score", "action_taken", "timestamp"],
        "properties": {
            "policy_id": {"bsonType": "objectId"},
            "source_ip": {"bsonType": "string"},
            "threat_score": {"bsonType": "int", "minimum": 0},
            "action_taken": {"bsonType": "string", "enum": ["ALLOWED", "BLOCKED", "FLAGGED"]},
            "timestamp": {"bsonType": "date"}
        }
    }
}
db.command({"create": "traffic_logs", "validator": log_validator})
print("[OK] 'traffic_logs' collection created with schema validation.\n")

print("STEP 2: Seed mock dataset")
print("======================================================")

# Insert Security Policies (Like Personas)
policies = [
    {"endpoint_name": "/api/users/login", "method": "POST", "max_payload_size": 2000, "auth_required": False},
    {"endpoint_name": "/api/payments/process", "method": "POST", "max_payload_size": 4000, "auth_required": True},
    {"endpoint_name": "/api/data/export", "method": "GET", "max_payload_size": 1000, "auth_required": True},
    {"endpoint_name": "/api/admin/config", "method": "PUT", "max_payload_size": 3000, "auth_required": True},
    {"endpoint_name": "/api/legacy/sync", "method": "GET", "max_payload_size": 5000, "auth_required": False} # Deprecated
]
policy_ids = db.security_policies.insert_many(policies).inserted_ids
print("[OK] Inserted 5 Security Policies.")

# Insert Traffic Logs (Like Chat Logs)
actions = ["ALLOWED", "BLOCKED", "FLAGGED"]
ips = ["192.168.1.10", "10.0.0.55", "172.16.2.8", "45.22.19.11", "203.0.113.4"]

logs = []
for _ in range(20):
    logs.append({
        "policy_id": random.choice(policy_ids),
        "source_ip": random.choice(ips),
        "threat_score": random.randint(0, 100),
        "action_taken": random.choice(actions),
        "timestamp": datetime.now() - timedelta(days=random.randint(1, 35))
    })
db.traffic_logs.insert_many(logs)
print("[OK] Inserted 20 traffic log entries.\n")

print("STEP 3: CRUD demonstrations")
print("======================================================")

# [CREATE] Valid Policy
new_policy = {"endpoint_name": "/api/webhook/github", "method": "POST", "max_payload_size": 6000, "auth_required": True}
valid_insert = db.security_policies.insert_one(new_policy)
print(f"[CREATE] Policy '/api/webhook/github' inserted with _id={valid_insert.inserted_id}")

# [CREATE-FAILED] Validation Test (max_payload_size = 50, which is below 500)
try:
    bad_policy = {"endpoint_name": "/api/test", "method": "GET", "max_payload_size": 50, "auth_required": False}
    db.security_policies.insert_one(bad_policy)
except Exception as e:
    print(f"[CREATE-FAILED] Validation rejected the document: {e}")

# [READ] Fetch a policy
read_policy = db.security_policies.find_one({"endpoint_name": "/api/payments/process"}, {"_id": 0, "endpoint_name": 1, "max_payload_size": 1})
print(f"[READ] {read_policy['endpoint_name']} -> max_payload_size: {read_policy['max_payload_size']}")

# [UPDATE] Update a policy
update_res = db.security_policies.update_one({"endpoint_name": "/api/data/export"}, {"$set": {"max_payload_size": 1500}})
print(f"[UPDATE] '/api/data/export' limit updated (modified_count={update_res.modified_count})")

# [DELETE] Remove deprecated policy
delete_res = db.security_policies.delete_one({"endpoint_name": "/api/legacy/sync"})
print(f"[DELETE] Policy '/api/legacy/sync' removed from the database.\n")


print("STEP 4: Aggregation pipelines")
print("======================================================")

# Pipeline 1: Average Threat Score per Endpoint
print("\n[AGGREGATION 1] Average Threat Score per Endpoint:")
pipeline_1 = [
    {"$group": {"_id": "$policy_id", "avg_threat": {"$avg": "$threat_score"}, "total_requests": {"$sum": 1}}},
    {"$lookup": {"from": "security_policies", "localField": "_id", "foreignField": "_id", "as": "policy_data"}},
    {"$unwind": "$policy_data"},
    {"$project": {"_id": 0, "endpoint": "$policy_data.endpoint_name", "avg_threat": {"$round": ["$avg_threat", 2]}, "total_requests": 1}},
    {"$sort": {"avg_threat": -1}}
]
for doc in db.traffic_logs.aggregate(pipeline_1):
    print(f"  - {doc['endpoint']:<25} avg_threat={doc['avg_threat']:<8} total_requests={doc['total_requests']}")

# Pipeline 2: Request Frequency by Action Taken (Allowed/Blocked)
print("\n[AGGREGATION 2] Request Frequency by Action Taken:")
pipeline_2 = [
    {"$group": {"_id": "$action_taken", "count": {"$sum": 1}}},
    {"$sort": {"count": -1}}
]
for doc in db.traffic_logs.aggregate(pipeline_2):
    print(f"  - {doc['_id'].lower():<20} count={doc['count']}")

# Pipeline 3: Most Targeted Endpoint (Last 30 Days)
print("\n[AGGREGATION 3] Most Targeted Endpoint (Last 30 Days):")
thirty_days_ago = datetime.now() - timedelta(days=30)
pipeline_3 = [
    {"$match": {"timestamp": {"$gte": thirty_days_ago}}},
    {"$group": {"_id": "$policy_id", "requests": {"$sum": 1}}},
    {"$sort": {"requests": -1}},
    {"$limit": 1},
    {"$lookup": {"from": "security_policies", "localField": "_id", "foreignField": "_id", "as": "policy_data"}},
    {"$unwind": "$policy_data"},
    {"$project": {"_id": 0, "endpoint": "$policy_data.endpoint_name", "requests": 1}}
]
top_target = list(db.traffic_logs.aggregate(pipeline_3))
if top_target:
    print(f"  - {top_target[0]['endpoint']} with {top_target[0]['requests']} requests")

print("\n======================================================")
print("DEMO COMPLETED...!")