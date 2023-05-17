import vt
from termcolor import colored
from os import system
import sys

client = vt.Client("33b79996281108a335b8ec4ec9a4600737d35723b964bca75ea3a722f45390bc")

analysis = None
filename = None
if len(sys.argv) > 1:
    filename = sys.argv[1]
else:
    filename = input("Filename: ")
system("clear")
print(f"Analysing {filename}..." )
with open(filename,"rb") as f:
    analysis = client.scan_file(f, wait_for_completion=True)
print("Generating Report..." )
report = client.get_object("/analyses/{}", analysis.id).to_dict()
stats = report["attributes"]["stats"]
system("clear")
print("--------------------REPORT STATUS--------------------")
for key in stats.keys():
    if key == "malicious" and stats[key] > 0:
        alert = colored(f"{stats[key]} flagged this to be {key}", "red", attrs=['reverse','blink'])
        print(alert)
    else:
        print(f"{stats[key]} flagged this to be {key}")
client.close()
