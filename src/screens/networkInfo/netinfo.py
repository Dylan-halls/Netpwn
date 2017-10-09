#!/usr/bin/env python

"""
This page will display the relevant network info
associated with the current interface on the device
"""
#system imports
import os

#kivy imports
from kivy.lang import Builder
from kivy.uix.screenmanager import Screen
from kivy.uix.floatlayout import FloatLayout
from kivy.uix.textinput import TextInput

class info(object):
    def __init__(self):
        self.ip = "192.168.0.1"

class InfoScreen(Screen, FloatLayout):
    def __init__(self, **kwargs):
        super(InfoScreen, self).__init__(**kwargs)
        Builder.load_file(os.path.abspath("src/screens/networkInfo/netinfo.kv"))
        t = TextInput(text="Hello", multiline=False, size_hint=(.6, .1), pos_hint={'x':.09, 'y':.5},
                      font_size=23, background_color=(14,51,244,0))
        self.add_widget(t)
