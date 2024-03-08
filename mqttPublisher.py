
import os
from time import sleep
import random

randTime = round(random.uniform(0.3, 1.0),1)
randTimePing = round(random.uniform(0.2, 0.5),1)


print("\n MQTT simulator generator Script by Emmanuel Ebong")


device = input("input  name of the device")
topic = input("input the topic here: ")
iterations = input("input the number of mqtt requests")

mosquittoBroker = '10.0.0.5'



for i in range(iterations):
    os.system(f"mosquitto_pub -h {mosquittoBroker} -t '{topic}/{device}'-m 'ON'")
    sleep(0.5)
    
    
print("\n Mqtt Publish done \n...")

