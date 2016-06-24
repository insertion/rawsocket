/*************************************************************************
	> File Name: os_daemon.c
	> Author: wanglei
	> Mail: 
	> Created Time: 2016年06月22日 星期三 16时05分34秒
    > Decription  :使标准输入输出不在打印到屏幕
 ************************************************************************/
static int os_daemon(int nochdir, int noclose)
{
	int devnull;

	if (chdir("/") < 0)
		return -1;

	devnull = open("/dev/null", O_RDWR);
	if (devnull < 0)
		return -1;

	if (dup2(devnull, STDIN_FILENO) < 0) {
		close(devnull);
		return -1;
	}

	if (dup2(devnull, STDOUT_FILENO) < 0) {
		close(devnull);
		return -1;
	}

	if (dup2(devnull, STDERR_FILENO) < 0) {
		close(devnull);
		return -1;
	}

	return 0;
}
