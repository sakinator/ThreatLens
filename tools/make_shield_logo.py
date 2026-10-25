import os
import subprocess
import shutil

# Master Cybersecurity Shield:
# 1. FLAT horizontal top shoulder (112, 112) to (400, 112) - heater shield armor
# 2. Parallel straight vertical side walls down to y=270
# 3. Swept armor hull to bottom point (256, 448)
# 4. Bold glowing cyan security CHECKMARK (verified protection)
# 5. ZERO circles, ZERO dots, ZERO rings (100% immune to location pin resemblance)

svg = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512" width="512" height="512">
  <defs>
    <!-- Background: Exact ThreatLens Cyber Black (#070B14) -->
    <radialGradient id="bgGrad" cx="50%" cy="40%" r="65%">
      <stop offset="0%" stop-color="#0E1728"/>
      <stop offset="60%" stop-color="#070B14"/>
      <stop offset="100%" stop-color="#020408"/>
    </radialGradient>

    <!-- Electric Cyan & Neon Blue Border Gradient -->
    <linearGradient id="shieldBorder" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#38BDF8"/>
      <stop offset="45%" stop-color="#00E5FF"/>
      <stop offset="100%" stop-color="#0284C7"/>
    </linearGradient>

    <!-- Left Armor Plate Facet -->
    <linearGradient id="leftFacet" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#0F243C"/>
      <stop offset="60%" stop-color="#0A1828"/>
      <stop offset="100%" stop-color="#050D18"/>
    </linearGradient>

    <!-- Right Armor Plate Facet -->
    <linearGradient id="rightFacet" x1="100%" y1="0%" x2="0%" y2="100%">
      <stop offset="0%" stop-color="#081726"/>
      <stop offset="60%" stop-color="#050F1A"/>
      <stop offset="100%" stop-color="#03080F"/>
    </linearGradient>

    <!-- Glowing Cyber Checkmark Gradient -->
    <linearGradient id="checkGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#7DD3FC"/>
      <stop offset="50%" stop-color="#00E5FF"/>
      <stop offset="100%" stop-color="#00B4D8"/>
    </linearGradient>

    <filter id="glowEffect" x="-20%" y="-20%" width="140%" height="140%">
      <feGaussianBlur stdDeviation="10" result="blur"/>
      <feMerge>
        <feMergeNode in="blur"/>
        <feMergeNode in="SourceGraphic"/>
      </feMerge>
    </filter>
  </defs>

  <!-- Deep Cyber Black Canvas matching app internals -->
  <rect width="512" height="512" rx="112" fill="url(#bgGrad)"/>
  <rect width="512" height="512" rx="112" fill="none" stroke="#1E293B" stroke-width="2" stroke-opacity="0.4"/>

  <!-- Ambient Cyan Shield Halo -->
  <path d="M 112,112 L 400,112 L 400,270 C 400,362 310,422 256,448 C 202,422 112,362 112,270 Z"
        fill="none" stroke="#00E5FF" stroke-width="18" opacity="0.14" filter="url(#glowEffect)"/>

  <!-- Left Armor Facet (Straight vertical side, flat top) -->
  <path d="M 112,112 L 256,112 L 256,448 C 202,422 112,362 112,270 Z"
        fill="url(#leftFacet)"/>

  <!-- Right Armor Facet -->
  <path d="M 256,112 L 400,112 L 400,270 C 400,362 310,422 256,448 Z"
        fill="url(#rightFacet)"/>

  <!-- Outer Solid Shield Beveled Border -->
  <path d="M 112,112 L 400,112 L 400,270 C 400,362 310,422 256,448 C 202,422 112,362 112,270 Z"
        fill="none" stroke="url(#shieldBorder)" stroke-width="9" stroke-linejoin="round" stroke-linecap="round"/>

  <!-- Central Vertical Spine Line -->
  <path d="M 256,116 L 256,444"
        stroke="#00E5FF" stroke-width="2.5" stroke-linecap="round" opacity="0.6"/>

  <!-- Chiseled Inset Shield Accent Line -->
  <path d="M 144,142 L 368,142 L 368,266 C 368,340 296,394 256,416 C 216,394 144,340 144,266 Z"
        fill="none" stroke="#00E5FF" stroke-width="2.5" stroke-opacity="0.35" stroke-dasharray="14 7"/>

  <!-- Bold Minimalist Security Checkmark (Iconic Security & Protection) -->
  <path d="M 194,272 L 238,316 L 322,216"
        fill="none" stroke="url(#checkGrad)" stroke-width="22" stroke-linecap="round" stroke-linejoin="round" filter="url(#glowEffect)"/>
</svg>"""

svg_path = 'D:/ThreatLens/assets/threatlens_logo.svg'
with open(svg_path, 'w', encoding='utf-8') as f:
    f.write(svg)
print('Wrote SVG')

# Render clean PNG
temp_profile = 'D:/ThreatLens/tools/edge_temp_shield2'
if os.path.exists(temp_profile):
    shutil.rmtree(temp_profile, ignore_errors=True)
os.makedirs(temp_profile, exist_ok=True)

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
    background: transparent;
  }}
  svg {{
    width: 512px;
    height: 512px;
    display: block;
  }}
</style>
</head>
<body>
{svg}
</body>
</html>"""

html_path = 'D:/ThreatLens/tools/shield_view2.html'
with open(html_path, 'w', encoding='utf-8') as f:
    f.write(html)

edge = r'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe'
png_out = 'D:/ThreatLens/assets/threatlens_logo.png'

cmd = [
    edge,
    '--headless=new',
    '--disable-gpu',
    f'--user-data-dir={temp_profile}',
    '--no-first-run',
    '--no-default-browser-check',
    '--window-size=512,512',
    '--hide-scrollbars',
    '--default-background-color=00000000',
    f'--screenshot={png_out}',
    html_path
]

res = subprocess.run(cmd, capture_output=True, text=True)
print('Render code:', res.returncode)
print('PNG size:', os.path.getsize(png_out))
shutil.rmtree(temp_profile, ignore_errors=True)
if os.path.exists(html_path):
    os.remove(html_path)
