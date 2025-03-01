import piexif
from PIL import Image
import io
import base64

# Create a 2x2 blue image
img = Image.new('RGB', (2,2), 'blue')

# Prepare some EXIF metadata
exif_dict = {
    "0th":{
        piexif.ImageIFD.Make: u"DummyMake",
        piexif.ImageIFD.Model: u"DummyModel",
        piexif.ImageIFD.XResolution: (72,1),
        piexif.ImageIFD.YResolution: (72,1),
        piexif.ImageIFD.Software: u"piexif"
    },
    "Exif":{
        piexif.ExifIFD.DateTimeOriginal: u"2023:01:01 12:00:00",
        piexif.ExifIFD.LensMake: u"DummyLensMake",
        piexif.ExifIFD.LensModel: u"DummyLensModel"
    }
}

exif_bytes = piexif.dump(exif_dict)

# Save to an in-memory buffer
bio = io.BytesIO()
img.save(bio, format="JPEG", exif=exif_bytes)

# Encode image in base64
encoded = base64.b64encode(bio.getvalue()).decode('utf-8')
encoded

