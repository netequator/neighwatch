import os

from PIL import Image, ImageDraw, ImageFont


def generate_gif():
    font_path = "C:/Windows/Fonts/consola.ttf"
    font_bold_path = "C:/Windows/Fonts/consolab.ttf"
    font = ImageFont.truetype(font_path, 13)
    font_bold = ImageFont.truetype(font_bold_path, 13)
    font_title = ImageFont.truetype(font_path, 11)

    width, height = 840, 370
    bg_color = (13, 17, 23)
    border_color = (48, 54, 61)
    bar_line = (33, 38, 45)
    dot_color = (33, 38, 45)
    dot_border = (48, 54, 61)
    text_muted = (110, 118, 129)
    text_white = (240, 246, 252)
    text_green = (126, 231, 135)
    text_blue = (121, 192, 255)
    text_red = (255, 123, 114)
    text_yellow = (210, 153, 34)
    text_purple = (210, 168, 255)
    prompt_green = (63, 185, 80)

    cmd_text = "neighwatch -i eth0 --state-file state.json --ttl 86400"

    events = [
        # (type, segments, box_color)
        ("text", [
            ('{"ts":', text_blue), ('"2026-11-17T06:50:01Z",', text_white),
            (' "event":', text_blue), ('"arp_learned",', text_green),
            (' "src_ip":', text_blue), ('"192.168.1.1",', text_blue),
            (' "src_mac":', text_blue), ('"52:54:00:12:34:56"', text_blue),
            ("}", text_white),
        ], None),
        ("text", [
            ('{"ts":', text_blue), ('"2026-11-17T06:50:03Z",', text_white),
            (' "event":', text_blue), ('"arp_learned",', text_green),
            (' "src_ip":', text_blue), ('"192.168.1.50",', text_blue),
            (' "src_mac":', text_blue), ('"00:50:56:c0:00:08",', text_blue),
            (' "vlan":', text_blue), ("10", text_purple),
            ("}", text_white),
        ], None),
        ("box_red", [
            ('{"ts":', text_red), ('"2026-11-17T06:50:08Z",', text_white),
            (' "event":', text_red), ('"arp_mac_change",', text_red),
            (' "severity":', text_red), ('"alert",', text_red),
            (' "src_ip":', text_blue), ('"192.168.1.1",', text_blue),
            (' "new_mac":', text_red), ('"de:ad:be:ef:00:01"', text_red),
            ("}", text_white),
        ], (248, 81, 73, 30)),
        ("text", [
            ('{"ts":', text_blue), ('"2026-11-17T06:50:12Z",', text_white),
            (' "event":', text_blue), ('"ndp_learned",', text_green),
            (' "src_ip":', text_blue), ('"fe80::1",', text_blue),
            (' "src_mac":', text_blue), ('"52:54:00:12:34:56"', text_blue),
            ("}", text_white),
        ], None),
        ("text", [
            ('{"ts":', text_blue), ('"2026-11-17T06:50:15Z",', text_white),
            (' "event":', text_blue), ('"ndp_dad_probe",', text_blue),
            (' "target_ip":', text_blue), ('"fe80::200:ff:fe00:1",', text_blue),
            (' "status":', text_blue), ('"quarantined"', text_muted),
            ("}", text_white),
        ], None),
        ("box_yellow", [
            ('{"ts":', text_yellow), ('"2026-11-17T06:50:19Z",', text_white),
            (' "event":', text_yellow), ('"ndp_invalid_hop_limit",', text_yellow),
            (' "src_ip":', text_blue), ('"fe80::bad",', text_blue),
            (' "hop_limit":', text_yellow), ("64,", text_red),
            (' "action":', text_muted), ('"dropped_offlink_spoof"', text_muted),
            ("}", text_white),
        ], (210, 153, 34, 25)),
    ]

    y_positions = [105, 138, 172, 212, 245, 280]

    def draw_base():
        img = Image.new("RGBA", (width, height), bg_color)
        d = ImageDraw.Draw(img)
        d.rounded_rectangle([1, 1, width - 2, height - 2], radius=8, outline=border_color, width=1)
        d.line([1, 38, width - 2, 38], fill=bar_line, width=1)
        for x in [24, 40, 56]:
            d.ellipse([x - 5, 20 - 5, x + 5, 20 + 5], fill=dot_color, outline=dot_border, width=1)
        d.text((width - 24, 14), "~/neighwatch (telemetry stream)", font=font_title, fill=text_muted, anchor="rt")
        return img, d

    frames = []
    durations = []

    # Step 1: Prompt typing
    type_steps = [
        "",
        "neighwatch -i eth0",
        "neighwatch -i eth0 --state-file state.json",
        cmd_text,
    ]
    for step in type_steps:
        base, d = draw_base()
        d.text((24, 60), "$", font=font_bold, fill=prompt_green)
        d.text((40, 60), step, font=font, fill=text_white)
        # cursor
        cmd_w = d.textlength(step, font=font) if step else 0
        d.text((40 + cmd_w + 3, 60), "_", font=font_bold, fill=prompt_green)
        frames.append(base.convert("RGB"))
        durations.append(350 if step != cmd_text else 600)

    # Step 2: Show events progressively
    for i in range(1, len(events) + 1):
        base, d = draw_base()
        d.text((24, 60), "$", font=font_bold, fill=prompt_green)
        d.text((40, 60), cmd_text, font=font, fill=text_white)

        for j in range(i):
            ev_type, segments, _box_bg = events[j]
            y = y_positions[j]

            if ev_type == "box_red":
                d.rounded_rectangle([20, y - 4, width - 20, y + 24], radius=4,
                                    fill=(40, 20, 24), outline=text_red, width=1)
            elif ev_type == "box_yellow":
                d.rounded_rectangle([20, y - 4, width - 20, y + 24], radius=4,
                                    fill=(35, 30, 20), outline=text_yellow, width=1)

            x = 24
            for text, color in segments:
                use_font = font_bold if (ev_type.startswith("box") and color in (text_red, text_yellow)) else font
                d.text((x, y), text, font=use_font, fill=color)
                x += int(d.textlength(text, font=use_font))

        if i == len(events):
            d.text((24, 325), "# listening on eth0 (bpf: arp or icmp6) ...", font=font, fill=text_muted)
            d.text((24 + int(d.textlength("# listening on eth0 (bpf: arp or icmp6) ...", font=font)) + 6, 325),
                   "_", font=font_bold, fill=prompt_green)

        frames.append(base.convert("RGB"))
        if i == 3: # Alert frame
            durations.append(1400)
        elif i == 6: # Warning frame
            durations.append(1200)
        elif i == len(events): # Final frame
            durations.append(3000)
        else:
            durations.append(800)

    # Save animated GIF
    out_path = "d:/agent 009/neighwatch/assets/demo.gif"
    frames[0].save(
        out_path,
        save_all=True,
        append_images=frames[1:],
        duration=durations,
        loop=0,
        optimize=True
    )
    print(f"GIF saved to {out_path} ({len(frames)} frames, total size: {os.path.getsize(out_path)} bytes)")

if __name__ == "__main__":
    generate_gif()
