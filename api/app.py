import os
from flask import Flask , render_template , jsonify , request
from supabase import create_client, Client
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

supabase: Client = create_client(
    os.environ.get("SUPABASE_URL"),
    os.environ.get("SUPABASE_PUBLISHABLE_KEY")
)

@app.route('/')
def index():
    try:
        # Fetch data
        response = supabase.table('attack_logs').select("*").execute()
        # print("response ", response)
        # In newer versions of the supabase-py library, use response.data
        logs = response.data 
        
        if not logs:
            return "<h1>Attack Logs</h1><p>Connected, but no data found. Check RLS policies.</p>"

        html = '<h1>Attack Logs</h1><ul>'
        for log in logs:
            html += f"<li>{log.get('timestamp')} | {log.get('source_ip')} → {log.get('dest_ip')}</li>"
        html += '</ul>'
        return html

    except Exception as e:
        return f"<h1>Error</h1><p>{str(e)}</p>"

@app.route('/store' , methods=['POST'])
def store():
    try:
        data  = request.get_json()

        required_fields = [
    "timestamp",
    "source_ip",
    "dest_ip",
    "dest_port",
    "protocol",
    "final_label",
    "is_attack",
    "decided_by",
    "dl_prediction",
    "dl_confidence",
    "heuristic_label",
    "unique_ports_seen",
    "flows_from_ip",
    "packet_count",
    "pkt_per_sec",
    "bytes_per_sec",
    "duration_ms",
      "syn",
      "fin",
      "rst",
      "ack" ,
      "psh"
    ]
        for field in required_fields:
            if field not in data:
                return jsonify({"error": f"{field} is required"}), 400


        response = supabase.table('attack_logs').insert(data).execute()
        # print("Insert response ", response)
        return jsonify({
            "message": "Stored successfully",
            "inserted": response.data
        }), 201

    except Exception as e:
        return jsonify({"error": str(e)}), 500    
# @app.route('/temp')
# def temp():
#     return render_template('index.html')        

if __name__ == '__main__':
    app.run(debug=True)