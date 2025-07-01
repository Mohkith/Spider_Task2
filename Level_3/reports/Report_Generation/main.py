from jinja2 import Environment, FileSystemLoader
import json


with open("E://BUG BOUNTY/example.json", "r") as f:  # Enter your own path where your output file is saved
    Recon_data = json.load(f)

env= Environment(loader=FileSystemLoader('templates'))
template = env.get_template('base.html')
html_report = template.render(Recon_data=Recon_data)

with open("recon_report.html", "w") as f:
    f.write(html_report)   
