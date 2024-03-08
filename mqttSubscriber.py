
import os
from time import sleep
import random

randTime = round(random.uniform(0.3, 1.0),1)
randTimePing = round(random.uniform(0.2, 0.5),1)
ipaddress = "10.0.0.9"  ### ip address of the victim here

print("\n MQTT simulator generator Script by Emmanuel Ebong")


device = input("input the name of the device you want to simulate here: ")
topic = input("input the topic here: ")
mosquittoBroker = '10.0.0.5'

print(f"registering the topic: {topic}  to the mqtt controller")
sleep(2)
os.system(f"mosquitto_sub -h {mosquittoBroker} -t '{topic}/{device}' ")
sleep(2)
print("\n Mqtt Topic Registered \n...")

