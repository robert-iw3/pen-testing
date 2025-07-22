from moviepy.editor import ColorClip, TextClip, CompositeVideoClip

sec = int(input("How long will this be 🎥(seconds): "))

def create_mp4_file(output_filename):
    # Create a color clip (red background)
    color_clip = ColorClip(size=(640, 480), color=(255, 0, 0), duration=sec)

    # Create a text clip (customize as needed)
    text_clip = TextClip("Hello, World!", fontsize=70, color='white')
    text_clip = text_clip.set_position('center').set_duration(sec)

    # Overlay text on the color clip
    video = CompositeVideoClip([color_clip, text_clip])

    # Write the result to a file (output as .mp4)
    video.write_videofile(output_filename, codec='libx264', fps=24)

# Usage
output_path = f"{input('file name: ')}.mp4"
create_mp4_file(output_path)
