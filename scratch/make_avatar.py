import os
import base64
from io import BytesIO
from PIL import Image, ImageDraw, ImageFilter

os.makedirs("assets", exist_ok=True)

# 1. Load the official base white and black logo images
logo_white_path = "assets/logo_white.png"
logo_black_path = "assets/logo_black.png"

white_img = Image.open(logo_white_path).convert("RGBA")
black_img = Image.open(logo_black_path).convert("RGBA")

SIZE = 1024
LOGO_SCALE = 600

# Resize with high-quality resampling
logo_w_resized = white_img.resize((LOGO_SCALE, LOGO_SCALE), Image.Resampling.LANCZOS)
logo_b_resized = black_img.resize((LOGO_SCALE, LOGO_SCALE), Image.Resampling.LANCZOS)

# --- Option 1: Obsidian Dark (GitHub Profile Dark Theme) ---
bg_dark = Image.new("RGBA", (SIZE, SIZE), (10, 10, 12, 255)) # Deep Obsidian #0a0a0c
# Center logo
offset = ((SIZE - LOGO_SCALE) // 2, (SIZE - LOGO_SCALE) // 2)
bg_dark.paste(logo_w_resized, offset, logo_w_resized)
dark_out = "assets/peitho_github_avatar_dark.png"
bg_dark.save(dark_out, "PNG")

# --- Option 2: Clean Minimalist Light (GitHub Profile Light Theme) ---
bg_light = Image.new("RGBA", (SIZE, SIZE), (255, 255, 255, 255))
bg_light.paste(logo_b_resized, offset, logo_b_resized)
light_out = "assets/peitho_github_avatar_light.png"
bg_light.save(light_out, "PNG")

# --- Option 3: Glowing Cyber Emerald Avatar ---
bg_emerald = Image.new("RGBA", (SIZE, SIZE), (8, 12, 10, 255))
draw = ImageDraw.Draw(bg_emerald)
# Subtle glowing radial ring behind logo
draw.ellipse([SIZE//2 - 340, SIZE//2 - 340, SIZE//2 + 340, SIZE//2 + 340], fill=(16, 185, 129, 30))
bg_emerald.paste(logo_w_resized, offset, logo_w_resized)
emerald_out = "assets/peitho_github_avatar_emerald.png"
bg_emerald.save(emerald_out, "PNG")

# Copy directly to Desktop for instant drag-and-drop
import shutil
shutil.copy(dark_out, "/Users/eddie/Desktop/peitho_github_avatar_dark.png")
shutil.copy(light_out, "/Users/eddie/Desktop/peitho_github_avatar_light.png")
shutil.copy(emerald_out, "/Users/eddie/Desktop/peitho_github_avatar_emerald.png")
print("✅ Generated 1024x1024 GitHub Avatars and copied to Desktop!")
