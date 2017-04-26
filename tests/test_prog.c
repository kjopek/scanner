#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/event.h>

#include <err.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int
main(int argc, char **argv)
{
	int kq, ret;
	struct kevent ev;
	pid_t ppid;

	/*
	 * Open kqueue.
	 */
	kq = kqueue();
	if (kq < 0)
		err(1, "kqueue(2) failed");

	/*
	 * Register handling of SIGSTOP.
	 */
	EV_SET(&ev, SIGSTOP, EVFILT_SIGNAL, EV_ADD | EV_ENABLE, 0, 0, 0);
	ret = kevent(kq, &ev, 1, NULL, 0, NULL);
	if (ret != 0)
		err(1,"kevent(2) failed");

	ppid = getppid();
	ret = 1;
	while (ret != 0) {
		/*
		 * Event loop. Take one event and handle it.
		 */
		ret = kevent(kq, NULL, 0, &ev, 1, NULL);
		if (ret < 0)
			err(1, "kevent(2) failed");
		if (ret == 1 && ev.filter == EVFILT_SIGNAL)
			printf("sigstop\n");

		if (ppid != getppid())
			printf("Parent changed");
	}
	return (ret);
}
