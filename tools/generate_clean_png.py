import os
import subprocess
import shutil

temp_dir = 'D:/ThreatLens/tools/edge_temp'
os.makedirs(temp_dir, exist_ok=True)

edge = r'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe'
svg_path = 'D:/ThreatLens/assets/threatlens_logo.svg'
png_out = 'D:/ThreatLens/assets/threatlens_logo.png'

# Read svg content directly to embed inline
with open(svg_path, 'r', encoding='utf-8') as f:
    svg_content = f.read()

# Ensure viewBox and dimensions are exactly 512x512
svg_content = svg_content.replace('width="100%" height="100%"', 'width="512" height="512"')

html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
  html, body {{
    margin: 0;
    padding: 0;
    width: 512px;
    height: 512px;
    overflow: hidden;
    background: #050813;
  }}
  svg {{
    width: 512px;
    height: 512px;
    display: block;
  }}
</style>
</head>
<body>
{svg_content}
</body>
</html>"""

html_path = 'D:/ThreatLens/tools/logo_viewer.html'
with open(html_path, 'w', encoding='utf-8') as f:
    f.write(html)

cmd = [
    edge,
    '--headless=new',
    f'--user-data-dir={temp_dir}',
    '--no-first-run',
    '--no-default-browser-check',
    '--disable-extensions',
    '--disable-background-networking',
    '--window-size=512,512',
    f'--screenshot={png_out}',
    f'file:///{html_path.replace(os.sep, "/")}'
]

subprocess.run(cmd, check=True)
size = os.path.getsize(png_out)
print(f"PNG Generated successfully! Size: {size} bytes")

shutil.rmtree(temp_dir, ignore_errors=True)
if os.path.exists(html_path):
    os.remove(html_path)
