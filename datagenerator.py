
import os
from time import sleep
import random

randTime = round(random.uniform(0.3, 1.0),1)
randTimePing = round(random.uniform(0.2, 0.5),1)
ipaddress = "10.0.0.9"  ### ip address of the victim here


print("\n Data generation Script by Emmanuel Ebong")

ipaddress = input("\n input your destination ip address here: ")
ceil = int(input("\n Test amount: [max 1000 , min 400] : ")) #max 1000, min



for i in range(1,ceil):
	randTime = round(random.uniform(0.3, 1.0),1)
	randTimePing = round(random.uniform(0.2, 0.5),1)
	print(f"\n Times :::  randTime {randTime} randTimePing {randTimePing}")
	os.system(f"wget {ipaddress}:8000")
	sleep(randTime)
	os.system(f"ping {ipaddress} -c 2")
	sleep(randTimePing)
	

	
	if i == 1:
		print(f"this is the 1st iteration \n")
	elif i == 2:
		print(f"this is the 2nd iteration \n")
	else:
		print(f"this is the {i}th iteration \n")
	


print("\n tcp and icmp generator generation complete \n...")


