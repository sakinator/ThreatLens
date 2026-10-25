import os
import subprocess

with open('D:/ThreatLens/assets/threatlens_logo.svg', 'r', encoding='utf-8') as f:
    svg_code = f.read()

# Replace viewBox width and height to fixed 512
svg_code = svg_code.replace('width="100%" height="100%"', 'width="512" height="512"')

html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  html, body {{ width: 512px; height: 512px; overflow: hidden; background: transparent; }}
  svg {{ width: 512px; height: 512px; display: block; }}
</style>
</head>
<body>
{svg_code}
</body>
</html>"""

html_path = 'D:/ThreatLens/assets/render_logo.html'
with open(html_path, 'w', encoding='utf-8') as f:
    f.write(html)

edge = r'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe'
png_out = r'D:\ThreatLens\assets\threatlens_logo.png'

cmd = [
    edge,
    '--headless=new',
    '--hide-scrollbars',
    '--window-size=512,512',
    '--default-background-color=00000000',
    f'--screenshot={png_out}',
    f'file:///{html_path.replace(os.sep, "/")}'
]

subprocess.run(cmd, check=True)
size = os.path.getsize(png_out)
print(f"Rendered PNG successfully! File size: {size} bytes")
