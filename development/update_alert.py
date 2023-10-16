# This script is used to convert TOML alert documentation to JSON, validate and enforce data, then upload it to Elastic via the Security API.

import requests
import os
import tomllib

url = "https://a03d60d07f6c4ccbb86cc0af9775d2df.us-central1.gcp.cloud.es.io:9243/api/detection_engine/rules"
api_key = os.environ["ELASTIC_KEY"]
headers = {
    'Content-Type': 'application/json',
    'kbn-xsrf': 'true',
    'Authorization': 'ApiKey ' + api_key
}

changed_files = os.environ["CHANGED_FILES"]

data = ""

# get to the directory we need, iterate over it, and print availble TOML files
for root, dirs, files in os.walk("detections/"):
    for file in files:
        if file in changed_files:
            data = "{\n" # creating the JSON syntax conversion with an opening curly braces and a newline (Enter)
            if file.endswith(".toml"):
                full_path = os.path.join(root, file) # Use root and file varialbes to create the path to the file
                with open(full_path,"rb") as toml:
                    alert = tomllib.load(toml)

                    # grabbing only the fields required by Elastic. Can be modified to include more fields.
                    if alert['rule']['type'] == "query": # query based alert
                        required_fields = ['author', 'description', 'name', 'rule_id', 'risk_score', 'severity', 'type', 'query', 'threat']
                    elif alert['rule']['type'] == "eql": # event correlation alert
                        required_fields = ['author', 'description', 'name', 'rule_id', 'risk_score', 'severity', 'type', 'query', 'language', 'threat']
                    elif alert['rule']['type'] == "threshold": # threshold based alert
                        required_fields = ['author', 'description', 'name', 'rule_id', 'risk_score', 'severity', 'type', 'query', 'threshold', 'threat']
                    else:
                        print("Unsupported rule type found in: " + full_path)
                        break

                # Converter code and more formatting!
                for field in alert['rule']:
                    if field in required_fields:
                        if type(alert['rule'][field]) == list:
                            data += "  " + "\"" + field + "\": " + str(alert['rule'][field]).replace("'", "\"") + "," + "\n"
                        elif type(alert['rule'][field]) == str:
                            data += "  " + "\"" + field + "\": \"" + str(alert['rule'][field]).replace("\n", " ").replace("\"", "\\\"") + "\"," + "\n"
                        elif type(alert['rule'][field]) == int:
                            data += "  " + "\"" + field + "\": " + str(alert['rule'][field]) + "," + "\n"
                        elif type(alert['rule'][field]) == dict:
                            data += "  " + "\"" + field + "\": " + str(alert['rule'][field]).replace("'", "\"") + "," + "\n"
            
            data += " \"enabled\": true\n}" # finishing JSON syntax conversion with a newline (Enter) and closing curly braces
        # print(data) # testing for "trouble" alerts when uploading to Elastic

        rule_id = alert['rule']['rule_id']
        url = url + "?rule_id=" + rule_id

        elastic_data = requests.put(url, headers=headers, data=data).json()
        print(elastic_data)



