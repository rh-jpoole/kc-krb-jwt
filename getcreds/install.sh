#!/bin/bash
pyinstaller --onefile /builderdir/getcreds.py --distpath /builderdir/dist --hidden-import configparser --hidden-import gssapi.raw.cython_converters
