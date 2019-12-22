#!/bin/sh
rshell --port /dev/cu.SLAB_USBtoUART cp main.py /pyboard/
rshell --port /dev/cu.SLAB_USBtoUART repl
