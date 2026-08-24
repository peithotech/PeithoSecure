#!/usr/bin/env python3
import base64
import os
from PIL import Image, ImageOps

src_path = "/Users/eddie/.gemini/antigravity/brain/b92d6f83-d3ee-4419-b690-dc24b6a2eef8/.user_uploaded/media_1787492293028.jpg"
out_dir = "/Users/eddie/Desktop/peithosecure/assets"
os.makedirs(out_dir, exist_ok=True)

img = Image.open(src_path).convert("RGBA")

# Grayscale to find bounding box
gray = ImageOps.grayscale(img)
# Invert so black logo becomes white for bbox detection
inverted = ImageOps.invert(gray)
# Threshold
thresholded = inverted.point(lambda p: 255 if p > 100 else 0)
bbox = thresholded.getbbox()

# Crop tightly with slight padding
cropped = img.crop(bbox)
w, h = cropped.size

# Square canvas
max_dim = max(w, h)
pad = int(max_dim * 0.08)
final_size = max_dim + pad * 2

# Black on transparent (Light mode)
black_img = Image.new("RGBA", (final_size, final_size), (0, 0, 0, 0))
# White on transparent (Dark mode)
white_img = Image.new("RGBA", (final_size, final_size), (0, 0, 0, 0))

# Process pixels
for x in range(w):
    for y in range(h):
        r, g, b, a = cropped.getpixel((x, y))
        brightness = (r + g + b) // 3
        if brightness < 140:
            # Black pixel in original -> opaque black in light mode, opaque white in dark mode
            alpha = int((1.0 - (brightness / 140.0)) * 255)
            black_img.putpixel((x + pad, y + pad), (0, 0, 0, 255))
            white_img.putpixel((x + pad, y + pad), (255, 255, 255, 255))

# Resize cleanly to 256x256 high-DPI
black_img = black_img.resize((256, 256), Image.Resampling.LANCZOS)
white_img = white_img.resize((256, 256), Image.Resampling.LANCZOS)

black_path = os.path.join(out_dir, "logo_black.png")
white_path = os.path.join(out_dir, "logo_white.png")

black_img.save(black_path, "PNG")
white_img.save(white_path, "PNG")

with open(black_path, "rb") as f:
    b64_black = base64.b64encode(f.read()).decode("utf-8")

with open(white_path, "rb") as f:
    b64_white = base64.b64encode(f.read()).decode("utf-8")

print(f"B64_BLACK_LEN: {len(b64_black)}")
print(f"B64_WHITE_LEN: {len(b64_white)}")

# Write Rust embedding file
rust_code = f'''//! High-DPI transparent logo assets derived from official drawing.

pub const LOGO_BLACK_B64: &str = "{b64_black}";
pub const LOGO_WHITE_B64: &str = "{b64_white}";
'''

with open("/Users/eddie/Desktop/peithosecure/crates/peitho-cli/src/ui/logo_data.rs", "w") as f:
    f.write(rust_code)

print("✅ Successfully generated pixel-perfect logo_data.rs!")
