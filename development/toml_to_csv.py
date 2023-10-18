import tomllib
import os

list = {}

for root, dirs, files in os.walk("detections/"):
    for file in files:
        if file.endswith(".toml"):
            full_path = os.path.join(root, file) # Use root and file varialbes to create the path to the file
            with open(full_path,"rb") as toml:
                alert = tomllib.load(toml)
                date = alert['metadata']['creation_date']
                name = alert['rule']['name']
                author = alert['rule']['author']
                risk_score = alert['rule']['risk_score']
                severity = alert['rule']['severity']
                
                filtered_object_array = []
                if alert['rule']['threat'][0]['framework'] == "MITRE ATT&CK": # the [0] is used to "go down" another level in JSON (square brackets)
                        for threat in alert['rule']['threat']:
                            technique_id = threat['technique'][0]['id']
                            technique_name = threat['technique'][0]['name']

                            if 'tactic' in threat:
                                tactic = threat['tactic']['name']
                            else: # this is for catching tactics that don't exist. Can remove to enforce tactic use
                                tactic = "none"
                            
                            if 'subtechnique' in threat['technique'][0]:
                                subtechnique_id = threat['technique'][0]['subtechnique'][0]['id']
                                subtechnique_name = threat['technique'][0]['subtechnique'][0]['name']
                            else: # this is for catching tactics that don't exist. Can replace with an error code.
                                subtechnique_id = "none"
                                subtechnique_name = "none"
                            
                            technique = technique_id + " - " + technique_name
                            subtech = subtechnique_id + " - " + subtechnique_name

                            obj = {'tactic': tactic, 'technique': technique, 'subtech': subtech, 'subtech': subtech}
                            filtered_object_array.append(obj)
                        obj = {'date': date, 'name': name, 'author': author, 'risk_score': risk_score, 'severity': severity, 'mitre': filtered_object_array}
                        list[file] = obj

# csv conversion
output_path = "metrics/detectionsdata.csv"
outF = open(output_path, "w")
outF.write("date,name,author,risk_score,severity,tactic,technique,subtechnique\n")


seperator = "; "
for line in list.values():
    date = line['date']
    name = line['name']
    author = str(line['author']).replace(",",";")
    risk_score = str(line['risk_score'])
    severity = line['severity']
    
    tactic = []
    tech = []
    subtech = []

    for technique in line['mitre']:
        tactic.append(technique['tactic'])
        tech.append(technique['technique'])
        subtech.append(technique['subtech'])
    outF.write(date + "," + name + ","+ author + ","+ risk_score + "," + severity + "," + seperator.join(tactic) + "," + seperator.join(tech) + "," + seperator.join(subtech) + "\n")
outF.close()


