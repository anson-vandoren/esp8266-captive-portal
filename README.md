# Blog post series

The code in this repo is the results of a blog series I wrote about building a captive web portal for a Wemos D1 Mini
using MicroPython. You can find the articles here:

- [Part 1](https://ansonvandoren.com/posts/esp8266-captive-web-portal-part-1/)
- [Part 2](https://ansonvandoren.com/posts/esp8266-captive-web-portal-part-2/)
- [Part 3](https://ansonvandoren.com/posts/esp8266-captive-web-portal-part-3/)
- [Part 4](https://ansonvandoren.com/posts/esp8266-captive-web-portal-part-4/)

# Starting the captive portal

Copy the .py and .html files to your ESP8266 board. If you already have a `main.py` file, then just copy the contents of
the `main.py` file from this repo. There's only a couple of lines there.

Instantiating a `CaptivePortal` and calling its `start()` method will turn on your MCU's WiFi access point, and you can
then connect to it and input your home WiFi credentials. Once you do, the MCU will turn off its AP, and connect to your
home WiFi instead.

# Purpose

This is not really a standalone project, but rather a bit of useful functionality that I drop into other projects
I make so that if I send one to someone else, I don't need to hardcode their home WiFi credentials to get the thing
to work. Instead, they can easily enter their own WiFi SSID and password to allow the device to connect and
start doing whatever it's supposed to be doing.
