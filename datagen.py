import os
from time import sleep

ceil = 1000
for i in range(ceil):
	os.system("wget 10.0.0.9:8000")
	sleep(0.8)
	os.system("ping 10.0.0.9 -c 2")
	sleep(0.4)
	print(f"this is the {i}th iteration \n")


print("tcp and icmp generator generation complete \n...")


