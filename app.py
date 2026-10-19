from flask import Flask, render_template_string, request
from Url_checker import check_single

app = Flask(__name__)

HTML = """
<!DOCTYPE html>
<html>
<head><title>URL Security Scanner</title>
<style>
body{font-family:Arial; background:#0f172a; color:white; text-align:center; padding:50px;}
input{padding:10px; width:300px;}
button{padding:10px 20px; background:#22c55e; border:none; cursor:pointer;}
.card{background:#1e293b; margin:20px auto; padding:20px; width:500px; border-radius:10px; text-align:left;}
.secure{color:#22c55e} .insecure{color:#ef4444}
</style>
</head>
<body>
<h1>🔒 URL Security Scanner</h1>
<form method="POST">
<input name="url" placeholder="Enter url e.g google.com" required>
<button>Scan</button>
</form>
{% if result %}
<div class="card">
<p><b>URL:</b> {{ result.url }}</p>
<p><b>Status:</b> <span class="{{ 'secure' if result.secure else 'insecure' }}">{{ 'SECURE' if result.secure else 'INSECURE' }}</span></p>
<p><b>SSL Days:</b> {{ result.ssl_days }} days</p>
<p><b>HTTP Status:</b> {{ result.status }}</p>
{% if result.virustotal %}
<p><b>VirusTotal:</b> {{ result.virustotal.malicious }} malicious, {{ result.virustotal.harmless }} harmless</p>
{% endif %}
</div>
{% endif %}
</body>
</html>
"""

@app.route('/', methods=['GET','POST'])
def home():
    result = None
    if request.method == 'POST':
        url = request.form.get('url')
        result = check_single(url)
    return render_template_string(HTML, result=result)

if __name__ == '__main__':
    app.run(debug=True)