import base64, io, sys, os
import gradio as gr
from io import BytesIO
from pathlib import Path
from typing import Optional
from urllib.parse import unquote
from fastapi import FastAPI, Request, Response
from PIL import Image as PILImage, PngImagePlugin, _util, ImagePalette

from modules.api import api
from modules.shared import opts
from modules import shared, sd_models, script_callbacks, scripts as md_scripts, images
from scripts.core.core import decrypt_image, decrypt_image_v2, decrypt_image_v3, get_sha256, encrypt_image_v3

RST = '\033[0m'
AR = f'\033[38;5;208m▶{RST}'
BLUE = '\033[38;5;39m'
RED = '\033[38;5;196m'
TITLE = 'Image Encryption:'

ckpt_dir = shared.cmd_opts.ckpt_dir or sd_models.model_path
lora_dir = shared.cmd_opts.lora_dir
emb_dir  = shared.cmd_opts.embeddings_dir
vae_dir  = Path(shared.models_path) / 'VAE'

repo_dir = md_scripts.basedir()
password = getattr(shared.cmd_opts, 'encrypt_pass', None)
api_enable = getattr(shared.cmd_opts, 'api', False)

class EncryptedImage(PILImage.Image):
    __name__ = "EncryptedImage"

    @staticmethod
    def from_image(image: PILImage.Image):
        image = image.copy()
        img = EncryptedImage()
        img.im = image.im
        img._mode = image.mode
        if image.im.mode:
            try:
                img.mode = image.im.mode
            except Exception:
                pass

        img._size = image.size
        img.format = image.format
        if image.mode in ("P", "PA"):
            img.palette = image.palette.copy() if image.palette else ImagePalette.ImagePalette()

        img.info = image.info.copy()
        return img

    def save(self, fp, format=None, **params):
        filename = ""
        encryption_type = self.info.get('Encrypt')

        if isinstance(fp, Path):
            filename = str(fp)
        elif _util.is_path(fp):
            filename = fp
        elif fp == sys.stdout:
            try:
                fp = sys.stdout.buffer
            except AttributeError:
                pass

        if not filename and hasattr(fp, "name") and _util.is_path(fp.name):
            filename = fp.name
            print(f'filename = {filename}')

        if not filename or not password:
            super().save(fp, format=format, **params)
            return

        if encryption_type in {'pixel_shuffle', 'pixel_shuffle_2', 'pixel_shuffle_3'}:
            super().save(fp, format=format, **params)
            return

        back_img = PILImage.new('RGBA', self.size)
        back_img.paste(self)

        self.paste(PILImage.fromarray(encrypt_image_v3(self, get_sha256(password))))
        self.format = PngImagePlugin.PngImageFile.format
        pnginfo = params.get('pnginfo', PngImagePlugin.PngInfo())
        if not pnginfo:
            pnginfo = PngImagePlugin.PngInfo()

        pnginfo.add_text('Encrypt', 'pixel_shuffle_3')
        pnginfo.add_text('EncryptPwdSha', get_sha256(f'{get_sha256(password)}Encrypt'))

        for key, value in self.info.items():
            if value is not None:
                if key == 'icc_profile':
                    continue
                if isinstance(value, bytes):
                    try:
                        pnginfo.add_text(key, value.decode('utf-8'))
                    except UnicodeDecodeError:
                        try:
                            pnginfo.add_text(key, value.decode('utf-16'))
                        except UnicodeDecodeError:
                            pnginfo.add_text(key, value.decode('utf-8', errors='replace'))
                            print(f"Error decoding '{key}' for file '{filename}' in saving image.")
                else:
                    pnginfo.add_text(key, str(value))

        params.update(pnginfo=pnginfo)
        super().save(fp, format=self.format, **params)
        self.paste(back_img)
        print(f"Encrypting: {filename}")
            
def hook_http_request(app: FastAPI):
    @app.middleware("http")
    async def image_decrypting(req: Request, call_next):
        endpoint: str = req.scope.get('path', 'err')
        endpoint = '/' + endpoint.strip('/')

        if endpoint.startswith('/infinite_image_browsing/image-thumbnail') or endpoint.startswith('/infinite_image_browsing/file'):
            query_string: str = req.scope.get('query_string').decode('utf-8')
            query_string = unquote(query_string)
            if query_string and query_string.index('path=') >= 0:
                query = query_string.split('&')
                path = ''
                for sub in query:
                    if sub.startswith('path='):
                        path = sub[sub.index('=') + 1:]
                if path:
                    endpoint = '/file=' + path

        if endpoint.startswith('/sd_extra_networks/thumb'):
            query_string: str = req.scope.get('query_string').decode('utf-8')
            query_string = unquote(query_string)
            if query_string and query_string.index('filename=') >= 0:
                query = query_string.split('&')
                path = ''
                for sub in query:
                    if sub.startswith('filename='):
                        path = sub[sub.index('=') + 1:]
                if path:
                    endpoint = '/file=' + path

        if endpoint.startswith('/file='):
            file_path = endpoint[6:]
            if not file_path or file_path.rfind('.') == -1:
                return await call_next(req)

            ext = file_path[file_path.rfind('.'):].lower()
            if ext in ['.png', '.jpg', '.jpeg', '.webp', '.avif']:
                image = PILImage.open(file_path)
                pnginfo = image.info or {}

                if 'Encrypt' not in pnginfo or 'EncryptPwdSha' not in pnginfo:
                    EncryptedImage.from_image(image).save(file_path)

                    image = PILImage.open(file_path)
                    pnginfo = image.info or {}

                buffered = BytesIO()
                info = PngImagePlugin.PngInfo()

                for key, value in pnginfo.items():
                    if value is not None:
                        if key == 'icc_profile':
                            continue
                        if isinstance(value, bytes):
                            try:
                                info.add_text(key, value.decode('utf-8'))
                            except UnicodeDecodeError:
                                try:
                                    info.add_text(key, value.decode('utf-16'))
                                except UnicodeDecodeError:
                                    info.add_text(key, str(value))
                                    print(f"Error decoding '{key}' in hook http. {file_path}")
                        else:
                            info.add_text(key, str(value))

                image.save(buffered, format=PngImagePlugin.PngImageFile.format, pnginfo=info)
                image_data = buffered.getvalue()
                response = Response(content=image_data, media_type="image/png")
                return response

        return await call_next(req)

def set_shared_options():
    section = ("encrypt_image_is_enable", "Encrypt image")
    option = shared.OptionInfo(default="Yes", label="Whether the encryption plug-in is enabled", section=section)
    option.do_not_save = True
    shared.opts.add_option("encrypt_image_is_enable", option)
    shared.opts.data['encrypt_image_is_enable'] = "Yes"

def encrypt_in_dir(folder: str):
    if not folder:
        return

    folder_path = Path(folder).resolve()
    if not folder_path.is_dir():
        return

    def process_image(file_path: Path):
        try:
            img = PILImage.open(file_path)
            pnginfo = img.info or {}

            if 'Encrypt' not in pnginfo or 'EncryptPwdSha' not in pnginfo:
                EncryptedImage.from_image(img).save(file_path)
        except Exception as e:
            print(f"Error processing {file_path}: {e}")

    for file_path in folder_path.rglob('*'):
        if file_path.is_file() and file_path.suffix.lower() in ['.png', '.jpg', '.jpeg', '.webp', '.avif']:
            process_image(file_path)

    for subdirectory in folder_path.iterdir():
        if subdirectory.is_dir():
            actual_path = subdirectory.resolve()

            for file_path in actual_path.rglob('*'):
                if file_path.is_file() and file_path.suffix.lower() in ['.png', '.jpg', '.jpeg', '.webp', '.avif']:
                    process_image(file_path)

def encode_pil_to_base64(img: PILImage.Image):
    pnginfo = img.info or {}

    with io.BytesIO() as output_bytes:
        if 'Encrypt' in pnginfo and pnginfo["Encrypt"] == 'pixel_shuffle_3':
            img.paste(PILImage.fromarray(decrypt_image_v3(img, get_sha256(password))))
        elif 'Encrypt' in pnginfo and pnginfo["Encrypt"] == 'pixel_shuffle_2':
            decrypt_image_v2(img, get_sha256(password))
        elif 'Encrypt' in pnginfo and pnginfo["Encrypt"] == 'pixel_shuffle':
            decrypt_image(img, get_sha256(password))

        pnginfo["Encrypt"] = None
        img.save(output_bytes, format=PngImagePlugin.PngImageFile.format, quality=opts.jpeg_quality)
        bytes_data = output_bytes.getvalue()

    return base64.b64encode(bytes_data)

def open(fp, *args, **kwargs):
    if not _util.is_path(fp) or not Path(fp).suffix:
        return super_open(fp, *args, **kwargs)

    if isinstance(fp, bytes):
        return encode_pil_to_base64(fp)

    img = super_open(fp, *args, **kwargs)
    pnginfo = img.info or {}

    if password and img.format.lower() == PngImagePlugin.PngImageFile.format.lower():
        if 'Encrypt' in pnginfo and pnginfo["Encrypt"] == 'pixel_shuffle_3':
            img.paste(PILImage.fromarray(decrypt_image_v3(img, get_sha256(password))))
        elif 'Encrypt' in pnginfo and pnginfo["Encrypt"] == 'pixel_shuffle_2':
            decrypt_image_v2(img, get_sha256(password))
        elif 'Encrypt' in pnginfo and pnginfo["Encrypt"] == 'pixel_shuffle':
            decrypt_image(img, get_sha256(password))

        pnginfo["Encrypt"] = None
        img = EncryptedImage.from_image(img)
        return img

    return EncryptedImage.from_image(img)
        
def api_middleware(app: FastAPI):
    super_api_middleware(app)
    hook_http_request(app)

def app_started_callback(_: gr.Blocks, app: FastAPI):
    set_shared_options()

    encrypt_in_dir(ckpt_dir)
    encrypt_in_dir(lora_dir)
    encrypt_in_dir(emb_dir)
    encrypt_in_dir(vae_dir)

if password == '':
    msg = f'{AR} {TITLE} {RED}Disabled{RST}, --encrypt-pass value is empty.'
elif not password and not api_enable:
    msg = f'{AR} {TITLE} {RED}Disabled{RST}, Missing --encrypt-pass and --api command line argument.'
elif not password:
    msg = f'{AR} {TITLE} {RED}Disabled{RST}, Missing --encrypt-pass command line argument.'
elif not api_enable:
    msg = f'{AR} {TITLE} {RED}Disabled{RST}, Missing --api command line argument.'
else:
    script_callbacks.on_app_started(app_started_callback)
    msg = f'{AR} {TITLE} {BLUE}Enabled{RST}, Encryption method 3.'

print(msg)

if PILImage.Image.__name__ != 'EncryptedImage':
    super_open = PILImage.open
    super_encode_pil_to_base64 = api.encode_pil_to_base64
    super_modules_images_save_image = images.save_image
    super_api_middleware = api.api_middleware

    if password:
        PILImage.Image = EncryptedImage
        PILImage.open = open
        api.encode_pil_to_base64 = encode_pil_to_base64
        api.api_middleware = api_middleware
