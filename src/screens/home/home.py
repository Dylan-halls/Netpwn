#!/usr/bin/env python

"""
This page is the base home and menu screen for the app
"""

#system imports
import os

#kivy imports
from kivy.lang import Builder
from kivy.uix.screenmanager import Screen
from kivy.uix.floatlayout import FloatLayout

class HomeScreen(Screen, FloatLayout):
    def __init__(self, **kwargs):
        super(HomeScreen, self).__init__(**kwargs)
        Builder.load_file(os.path.abspath("src/screens/home/home.kv"))
