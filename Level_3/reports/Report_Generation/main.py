from flask import Flask
from jinja2 import Environment, FileSystemLoader
import json

with open("E://BUG BOUNTY/example.json", "r") as f:  # Enter your own path where your output file is saved
    Recon_data = json.load(f)


# Use this code to get an output file named recon_report.html

env= Environment(loader=FileSystemLoader('templates'))
template = env.get_template('base.html')
html_report = template.render(Recon_data=Recon_data)

with open("recon_report.html", "w") as f:
    f.write(html_report)   

# Use this code to view the output in a website

app = Flask(__name__,template_folder='templates')

@app.route('/')
def index():
    return render_template('base.html', Recon_data=Recon_data)

if __name__ == "__main__":
    app.run(debug=True)
    

