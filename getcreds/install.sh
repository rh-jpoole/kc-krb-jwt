#!/bin/bash
pyinstaller --onefile /builderdir/getcreds.py --distpath /builderdir/dist --hidden-import configparser
