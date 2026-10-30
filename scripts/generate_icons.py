import math
from PIL import Image, ImageDraw

def create_aegis_icon(size=512):
    # Create RGBA image with dark cyber background
    img = Image.new("RGBA", (size, size), (3, 7, 18, 255))
    draw = ImageDraw.Draw(img)

    scale = size / 512.0
    cx, cy = size / 2, size / 2

    # Outer decorative cyber circle
    draw.ellipse(
        [cx - 220 * scale, cy - 220 * scale, cx + 220 * scale, cy + 220 * scale],
        outline=(14, 116, 144, 180),
        width=max(1, int(3 * scale))
    )

    # Shield polygon points
    shield_pts = [
        (256 * scale, 60 * scale),
        (400 * scale, 120 * scale),
        (390 * scale, 260 * scale),
        (256 * scale, 420 * scale),
        (122 * scale, 260 * scale),
        (112 * scale, 120 * scale),
    ]

    # Draw outer glow outline
    draw.polygon(shield_pts, fill=(8, 51, 68, 255), outline=(34, 211, 238, 255))

    # Inner shield
    inner_pts = [
        (256 * scale, 75 * scale),
        (385 * scale, 130 * scale),
        (375 * scale, 250 * scale),
        (256 * scale, 395 * scale),
        (137 * scale, 250 * scale),
        (127 * scale, 130 * scale),
    ]
    draw.polygon(inner_pts, fill=(15, 23, 42, 255), outline=(6, 182, 212, 255))

    # Radar rings inside shield
    center_y = 235 * scale
    for r in [90 * scale, 60 * scale, 30 * scale]:
        draw.ellipse([cx - r, center_y - r, cx + r, center_y + r], outline=(6, 182, 212, 160), width=max(1, int(2 * scale)))

    # Crosshairs
    draw.line([cx, center_y - 95 * scale, cx, center_y + 95 * scale], fill=(34, 211, 238, 200), width=max(1, int(2 * scale)))
    draw.line([cx - 95 * scale, center_y, cx + 95 * scale, center_y], fill=(34, 211, 238, 200), width=max(1, int(2 * scale)))

    # Radar blips
    draw.ellipse([cx - 45 * scale, center_y - 40 * scale, cx - 35 * scale, center_y - 30 * scale], fill=(56, 189, 248, 255))
    draw.ellipse([cx + 50 * scale, center_y - 20 * scale, cx + 60 * scale, center_y - 10 * scale], fill=(16, 185, 129, 255))
    draw.ellipse([cx + 30 * scale, center_y + 50 * scale, cx + 42 * scale, center_y + 62 * scale], fill=(244, 63, 94, 255)) # Red threat blip
    draw.ellipse([cx - 55 * scale, center_y + 35 * scale, cx - 45 * scale, center_y + 45 * scale], fill=(168, 85, 247, 255))

    # Core node
    r_core = 10 * scale
    draw.ellipse([cx - r_core, center_y - r_core, cx + r_core, center_y + r_core], fill=(34, 211, 238, 255))
    r_inner = 4 * scale
    draw.ellipse([cx - r_inner, center_y - r_inner, cx + r_inner, center_y + r_inner], fill=(255, 255, 255, 255))

    return img

if __name__ == "__main__":
    img512 = create_aegis_icon(512)
    img512.save("frontend/static/img/icon.png", format="PNG")
    img256 = create_aegis_icon(256)
    img256.save("frontend/static/img/icon-256.png", format="PNG")

    # Generate multi-size ICO for Windows
    sizes = [(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]
    icon_images = [create_aegis_icon(s[0]) for s in sizes]
    icon_images[0].save("frontend/static/img/icon.ico", format="ICO", sizes=sizes)
    icon_images[0].save("frontend/static/favicon.ico", format="ICO", sizes=[(16, 16), (32, 32), (48, 48)])
    icon_images[0].save("icon.ico", format="ICO", sizes=sizes)
    print("Icon assets successfully created!")
