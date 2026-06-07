from modules.script_callbacks import on_app_started
from sd_image_encryption import password, app

RST = '\033[0m'
ORG = '\033[38;5;208m'
BLUE = '\033[38;5;39m'
RED = '\033[38;5;196m'
AR = f'{BLUE}●{RST}'
TITLE = 'Image Encryption:'

d = f'{RED}Disabled{RST}'
e = f'{BLUE}Enabled{RST}'
t = 'Check the release page for decrypting images locally on Windows https://github.com/gutris1/sd-image-encryption'

v = f'{ORG}7.1{RST}'

if password == '': print(f'{AR} {TITLE} {d}, --encrypt-pass value is empty.')
elif not password: print(f'{AR} {TITLE} {d}, Missing --encrypt-pass command line argument.')
else:
    print(f'{AR} {TITLE} {e} {v}\n{AR} {TITLE} {t}')
    on_app_started(app)
