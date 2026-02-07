// SPDX-License-Identifier: GPL-2.0
/*
 * Test PR_SET/PR_GET_SCHED_LLC_AGGR_TOLERANCE prctl interface
 */

#include <errno.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdlib.h>

extern char **environ;

#include "kselftest_harness.h"

#ifndef PR_GET_SCHED_LLC_AGGR_TOLERANCE
#define PR_GET_SCHED_LLC_AGGR_TOLERANCE			79
#define PR_SET_SCHED_LLC_AGGR_TOLERANCE			80
# define PR_SCHED_LLC_AGGR_TOLERANCE_NR			0
# define PR_SCHED_LLC_AGGR_TOLERANCE_SIZE		1
# define PR_SCHED_LLC_AGGR_TOLERANCE_DEFAULT		-1
# define PR_SCHED_LLC_AGGR_TOLERANCE_FLAGS		2
# define PR_SCHED_LLC_AGGR_TOLERANCE_OVERLOAD_PCT	3
# define PR_SCHED_LLC_AGGR_TOLERANCE_FLAG_INHERIT_NR	(1UL << 0)
# define PR_SCHED_LLC_AGGR_TOLERANCE_FLAG_INHERIT_SIZE	(1UL << 1)
# define PR_SCHED_LLC_AGGR_TOLERANCE_FLAG_INHERIT_OVERLOAD_PCT	(1UL << 2)
#endif

static int llc_tol_set(unsigned long option, long val)
{
	int ret;

	ret = prctl(PR_SET_SCHED_LLC_AGGR_TOLERANCE, option,
		    (unsigned long)val, 0, 0);
	if (ret < 0)
		return -errno;
	return ret;
}

static int llc_tol_get(unsigned long option)
{
	int ret;

	ret = prctl(PR_GET_SCHED_LLC_AGGR_TOLERANCE, option, 0, 0, 0);
	if (ret < 0)
		return -errno;
	return ret;
}

static bool llc_tol_supported(void)
{
	int ret = llc_tol_get(PR_SCHED_LLC_AGGR_TOLERANCE_NR);

	if (ret == -EINVAL || ret == -ENOSYS)
		return false;
	return true;
}

static int exec_check(long expect_nr, long expect_size, long expect_overload)
{
	pid_t pid;
	int status;
	char nr_buf[32];
	char size_buf[32];
	char overload_buf[32];
	char *argv[] = { (char *)"sched-llc-aggr-tolerance", NULL };

	pid = fork();
	if (pid < 0)
		return -errno;
	if (pid == 0) {
		snprintf(nr_buf, sizeof(nr_buf), "%ld", expect_nr);
		snprintf(size_buf, sizeof(size_buf), "%ld", expect_size);
		snprintf(overload_buf, sizeof(overload_buf), "%ld", expect_overload);
		setenv("LLC_EXEC_MODE", "1", 1);
		setenv("LLC_EXEC_EXPECT_NR", nr_buf, 1);
		setenv("LLC_EXEC_EXPECT_SIZE", size_buf, 1);
		setenv("LLC_EXEC_EXPECT_OVERLOAD", overload_buf, 1);
		execve("/proc/self/exe", argv, environ);
		_exit(1);
	}

	if (waitpid(pid, &status, 0) != pid)
		return -errno;
	if (!WIFEXITED(status))
		return -ECHILD;
	if (WEXITSTATUS(status) != 0)
		return -EINVAL;
	return 0;
}

TEST(set_get_tolerances)
{
	int ret;

	if (!llc_tol_supported())
		SKIP(return, "sched cache prctl not supported");

	ret = llc_tol_set(PR_SCHED_LLC_AGGR_TOLERANCE_NR, 7);
	ASSERT_EQ(ret, 0);

	ret = llc_tol_set(PR_SCHED_LLC_AGGR_TOLERANCE_SIZE, 13);
	ASSERT_EQ(ret, 0);

	ret = llc_tol_set(PR_SCHED_LLC_AGGR_TOLERANCE_OVERLOAD_PCT, 55);
	ASSERT_EQ(ret, 0);

	ret = llc_tol_get(PR_SCHED_LLC_AGGR_TOLERANCE_NR);
	ASSERT_EQ(ret, 7);

	ret = llc_tol_get(PR_SCHED_LLC_AGGR_TOLERANCE_SIZE);
	ASSERT_EQ(ret, 13);

	ret = llc_tol_get(PR_SCHED_LLC_AGGR_TOLERANCE_OVERLOAD_PCT);
	ASSERT_EQ(ret, 55);

	ret = llc_tol_set(PR_SCHED_LLC_AGGR_TOLERANCE_NR, 101);
	ASSERT_EQ(ret, -EINVAL);

	ret = llc_tol_set(PR_SCHED_LLC_AGGR_TOLERANCE_SIZE, 101);
	ASSERT_EQ(ret, -EINVAL);

	ret = llc_tol_set(PR_SCHED_LLC_AGGR_TOLERANCE_OVERLOAD_PCT, 101);
	ASSERT_EQ(ret, -EINVAL);
}

TEST(flags_and_inheritance)
{
	int ret;
	pid_t pid;
	int status;

	if (!llc_tol_supported())
		SKIP(return, "sched cache prctl not supported");

	ret = llc_tol_set(PR_SCHED_LLC_AGGR_TOLERANCE_NR, 9);
	ASSERT_EQ(ret, 0);

	ret = llc_tol_set(PR_SCHED_LLC_AGGR_TOLERANCE_SIZE, 11);
	ASSERT_EQ(ret, 0);

	ret = llc_tol_set(PR_SCHED_LLC_AGGR_TOLERANCE_OVERLOAD_PCT, 44);
	ASSERT_EQ(ret, 0);

	ret = llc_tol_set(PR_SCHED_LLC_AGGR_TOLERANCE_FLAGS,
			  PR_SCHED_LLC_AGGR_TOLERANCE_FLAG_INHERIT_NR |
			  PR_SCHED_LLC_AGGR_TOLERANCE_FLAG_INHERIT_SIZE |
			  PR_SCHED_LLC_AGGR_TOLERANCE_FLAG_INHERIT_OVERLOAD_PCT);
	ASSERT_EQ(ret, 0);

	ret = llc_tol_get(PR_SCHED_LLC_AGGR_TOLERANCE_FLAGS);
	ASSERT_EQ(ret,
		  PR_SCHED_LLC_AGGR_TOLERANCE_FLAG_INHERIT_NR |
		  PR_SCHED_LLC_AGGR_TOLERANCE_FLAG_INHERIT_SIZE |
		  PR_SCHED_LLC_AGGR_TOLERANCE_FLAG_INHERIT_OVERLOAD_PCT);

	ret = llc_tol_set(PR_SCHED_LLC_AGGR_TOLERANCE_FLAGS, 0);
	ASSERT_EQ(ret, 0);

	ret = llc_tol_get(PR_SCHED_LLC_AGGR_TOLERANCE_FLAGS);
	ASSERT_EQ(ret, 0);

	pid = fork();
	ASSERT_GE(pid, 0);
	if (pid == 0) {
		int nr = llc_tol_get(PR_SCHED_LLC_AGGR_TOLERANCE_NR);
		int size = llc_tol_get(PR_SCHED_LLC_AGGR_TOLERANCE_SIZE);
		int overload = llc_tol_get(PR_SCHED_LLC_AGGR_TOLERANCE_OVERLOAD_PCT);

		if (nr != 9 || size != 11 || overload != 44)
			_exit(1);
		_exit(0);
	}

	ASSERT_EQ(waitpid(pid, &status, 0), pid);
	ASSERT_TRUE(WIFEXITED(status));
	ASSERT_EQ(WEXITSTATUS(status), 0);
}

TEST(execve_inheritance)
{
	int ret;

	if (!llc_tol_supported())
		SKIP(return, "sched cache prctl not supported");

	ret = llc_tol_set(PR_SCHED_LLC_AGGR_TOLERANCE_NR, 21);
	ASSERT_EQ(ret, 0);

	ret = llc_tol_set(PR_SCHED_LLC_AGGR_TOLERANCE_SIZE, 22);
	ASSERT_EQ(ret, 0);

	ret = llc_tol_set(PR_SCHED_LLC_AGGR_TOLERANCE_OVERLOAD_PCT, 66);
	ASSERT_EQ(ret, 0);

	ret = llc_tol_set(PR_SCHED_LLC_AGGR_TOLERANCE_FLAGS, 0);
	ASSERT_EQ(ret, 0);

	ret = exec_check(PR_SCHED_LLC_AGGR_TOLERANCE_DEFAULT,
			 PR_SCHED_LLC_AGGR_TOLERANCE_DEFAULT,
			 PR_SCHED_LLC_AGGR_TOLERANCE_DEFAULT);
	ASSERT_EQ(ret, 0);

	ret = llc_tol_set(PR_SCHED_LLC_AGGR_TOLERANCE_FLAGS,
			  PR_SCHED_LLC_AGGR_TOLERANCE_FLAG_INHERIT_NR |
			  PR_SCHED_LLC_AGGR_TOLERANCE_FLAG_INHERIT_SIZE |
			  PR_SCHED_LLC_AGGR_TOLERANCE_FLAG_INHERIT_OVERLOAD_PCT);
	ASSERT_EQ(ret, 0);

	ret = exec_check(21, 22, 66);
	ASSERT_EQ(ret, 0);
}

int main(int argc, char **argv)
{
	const char *mode = getenv("LLC_EXEC_MODE");

	if (mode && *mode) {
		long expect_nr = strtol(getenv("LLC_EXEC_EXPECT_NR"), NULL, 10);
		long expect_size = strtol(getenv("LLC_EXEC_EXPECT_SIZE"), NULL, 10);
		long expect_overload = strtol(getenv("LLC_EXEC_EXPECT_OVERLOAD"), NULL, 10);
		int nr = llc_tol_get(PR_SCHED_LLC_AGGR_TOLERANCE_NR);
		int size = llc_tol_get(PR_SCHED_LLC_AGGR_TOLERANCE_SIZE);
		int overload = llc_tol_get(PR_SCHED_LLC_AGGR_TOLERANCE_OVERLOAD_PCT);

		if (nr != expect_nr || size != expect_size ||
		    overload != expect_overload)
			return 1;
		return 0;
	}

	return test_harness_run(argc, argv);
}
