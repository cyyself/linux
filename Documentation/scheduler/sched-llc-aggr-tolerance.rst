======================
Cache Aware Scheduler
======================

The cache-aware scheduler can aggregate tasks that share a last-level cache
(LLC). The per-mm LLC aggregation tolerance controls how much aggregation
is allowed by limiting the number and size of tasks that can share an LLC.

When enabled, the scheduler prefers placing tasks with the same
``mm_struct`` on CPUs that share an LLC to improve cache locality and
reduce memory traffic. The tolerance values act as soft limits: higher
values allow more co-location before the scheduler treats the LLC as
effectively full, while lower values favor spreading tasks across LLCs to
reduce memory bandwidth pressure within the LLC. The number-based
tolerance limits how many tasks from the same ``mm_struct`` can be
aggregated within a single LLC, and the size-based tolerance limits the
aggregate working set size allowed to reside within that LLC.

It's notable that the working set size is measured by the RSS of the tasks
sharing the LLC, which may differ from the actual cache footprint. This
approach provides a practical approximation for managing cache pressure
without the complexity of tracking precise cache usage. Thus, users may
need to tune the size-based tolerance based on their application's memory
access patterns to achieve optimal performance.

This interface is available when the kernel is built with
``CONFIG_SCHED_CACHE``.

PR_SET/PR_GET_SCHED_LLC_AGGR_TOLERANCE
======================================

Set
---

.. code-block:: c

   int prctl(PR_SET_SCHED_LLC_AGGR_TOLERANCE,
             unsigned long option,
             unsigned long val);

``option`` selects the value to set:

* ``PR_SCHED_LLC_AGGR_TOLERANCE_NR``
* ``PR_SCHED_LLC_AGGR_TOLERANCE_SIZE``
* ``PR_SCHED_LLC_AGGR_TOLERANCE_FLAGS``
* ``PR_SCHED_LLC_AGGR_TOLERANCE_OVERLOAD_PCT``

For ``PR_SCHED_LLC_AGGR_TOLERANCE_NR``,
``PR_SCHED_LLC_AGGR_TOLERANCE_SIZE``, and
``PR_SCHED_LLC_AGGR_TOLERANCE_OVERLOAD_PCT``, ``val`` must be in the range
0..100, or ``PR_SCHED_LLC_AGGR_TOLERANCE_DEFAULT`` (-1) to use the system
default.

For ``PR_SCHED_LLC_AGGR_TOLERANCE_NR``, ``val`` sets the scale of the
number of cores in a LLC by which to compare the number of active threads
of the task's ``mm_struct``. Suppose the number of Cores in a LLC is 8.
The ``PR_SCHED_LLC_AGGR_TOLERANCE_NR`` value of 1 means that when the number of
active threads is larger than 8, the process is regarded as exceeding the LLC
capacity. The value of 99 means that when the number of active threads is
larger than 785, the process is regarded as exceeding the LLC capacity:
785 = 1 + (99 - 1) * 8. When it set to 100, there is no limit on the number of
active threads.

For ``PR_SCHED_LLC_AGGR_TOLERANCE_SIZE``, ``val`` sets the scale of the LLC
size by which to compare the task's RSS. Suppose the LLC size is 32MB.
The ``PR_SCHED_LLC_AGGR_TOLERANCE_SIZE`` value of 1 means that when the RSS
is larger than 32MB, the process is regarded as exceeding the LLC capacity. The
value of 99 means that when the RSS is larger than 3200MB, the process is
regarded as exceeding the LLC capacity:
3200MB = (1 + (99 - 1) * 1) * 32MB. When it set to 100, there is no limit on the RSS.

For ``PR_SCHED_LLC_AGGR_TOLERANCE_OVERLOAD_PCT``, ``val`` sets the overload
threshold as a percentage of LLC capacity used to decide when an LLC is
considered busy for aggregation. A value of 50 means aggregation is allowed
while LLC utilization is below 50% of capacity. A value of 100 disables the
busy check.

For ``PR_SCHED_LLC_AGGR_TOLERANCE_FLAGS``, ``val`` is a bitmask of:

* ``PR_SCHED_LLC_AGGR_TOLERANCE_FLAG_INHERIT_NR``
* ``PR_SCHED_LLC_AGGR_TOLERANCE_FLAG_INHERIT_SIZE``
* ``PR_SCHED_LLC_AGGR_TOLERANCE_FLAG_INHERIT_OVERLOAD_PCT``

If set, the corresponding tolerance value is inherited by child tasks that
by ``execve()`` when the inherit flag is set. These parameters will always
inherit from the parent task at ``fork()``.

Get
---

.. code-block:: c

   int prctl(PR_GET_SCHED_LLC_AGGR_TOLERANCE,
             unsigned long option,
             unsigned long arg2,
             unsigned long arg3,
             unsigned long arg4);

``option`` is the same as for ``PR_SET_SCHED_LLC_AGGR_TOLERANCE``. The return
value is the current setting for the requested ``option``.

Errors
------

* ``-EINVAL`` for invalid ``option`` or out-of-range ``val``.
* ``-ENOSYS`` or ``-EINVAL`` if the interface is not supported by the running
  kernel.
