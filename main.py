#!/usr/bin/env python

#Kivy imports
from kivy.app import App
from kivy.base import runTouchApp
from kivy.lang import Builder
from kivy.vector import Vector
from kivy.uix.image import Image
from kivy.uix.label import Label
from kivy.uix.button import Button
from kivy.uix.widget import Widget
from kivy.uix.floatlayout import FloatLayout
from kivy.uix.behaviors import ButtonBehavior
from kivy.uix.screenmanager import ScreenManager, Screen, NoTransition

#system imports
import os
import sys

#3rd party imports
import netifaces

#create paths
sys.path.append(os.path.abspath("src/screens/networkInfo"))
sys.path.append(os.path.abspath("src/screens/home"))

#netpwn imports
from netinfo import InfoScreen
from home import HomeScreen

"""def __init__(self):
        self.iface = netifaces.gateways()['default'][netifaces.AF_INET][1].decode('utf-8')
        self.mac = netifaces.ifaddresses(self.iface)[netifaces.AF_LINK][0]['addr']
        self.ip = netifaces.ifaddresses(self.iface)[netifaces.AF_INET][0]['addr']
"""

class Netpwn(App):
    def __init__(self, **kwargs):
        super(Netpwn, self).__init__(**kwargs)
        self.sm = ScreenManager()
        self.sm.add_widget(HomeScreen(name='Home'))
        self.sm.add_widget(InfoScreen(name='Info'))
        self.sm.switch_to(HomeScreen(name='Home'), transition=NoTransition())

    def scanTargets(self):
        print("Scanning...")

    def attackNetwork(self):
        print("Attacking Network...")

    def stopNetwork(self):
        print("Stopping Network...")

    def yourInfo(self):
        self.sm.switch_to(InfoScreen(name='Info'), transition=NoTransition())
        print("Your Info")

    def build(self):
        self.title = 'Netpwn'
        self.icon = os.path.abspath("/Images/bolt.png")
        return self.sm

if __name__ == "__main__":
    pwn = Netpwn()
    pwn.run()
