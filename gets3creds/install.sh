#!/bin/bash
pyinstaller --onefile /builderdir/gets3creds.py --distpath /builderdir/dist --hidden-import configparser
