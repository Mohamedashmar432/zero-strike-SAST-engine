# ZS-PY-093: a Pillow ImageMath expression built from form input.
from PIL import Image, ImageMath


def apply(request):
    function_str = request.POST.get("function")
    img = Image.open("base.png")
    return ImageMath.eval(function_str, a=img)
