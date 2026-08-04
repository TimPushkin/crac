// Copyright 2019, 2026 Azul Systems, Inc.  All Rights Reserved.
// DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
//
// This code is free software; you can redistribute it and/or modify it under
// the terms of the GNU General Public License version 2 only, as published by
// the Free Software Foundation.
//
// This code is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
// A PARTICULAR PURPOSE.  See the GNU General Public License version 2 for more
// details (a copy is included in the LICENSE file that accompanied this code).
//
// You should have received a copy of the GNU General Public License version 2
// along with this work; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
//
// Please contact Azul Systems, 385 Moffett Park Drive, Suite 115, Sunnyvale,
// CA 94089 USA or visit www.azul.com if you need additional information or
// have any questions.

// AI Tool Usage BOM
// ------------------
//
// AI Tools Used:
// - Anthropic Claude Opus 5
//

import jdk.crac.CheckpointException;
import jdk.crac.Context;
import jdk.crac.Resource;
import jdk.crac.RestoreException;
import jdk.crac.management.CRaCMXBean;
import jdk.test.lib.Utils;
import jdk.test.lib.crac.CracBuilder;
import jdk.test.lib.crac.CracEngine;
import jdk.test.lib.crac.CracTest;
import jdk.test.lib.crac.CracTestArg;

import java.lang.management.ManagementFactory;
import java.lang.management.ThreadInfo;
import java.lang.management.ThreadMXBean;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/*
 * @test id=SHA1PRNG
 * @summary Verify that SHA1PRNG secure random is not interlocked during checkpoint/restore.
 * @library /test/lib
 * @build InterlockTest
 * @run driver/timeout=60 jdk.test.lib.crac.CracTest SHA1PRNG
 */
/*
 * @test id=NativePRNGNonBlocking
 * @summary Verify that NativePRNGNonBlocking secure random is not interlocked during checkpoint/restore.
 * @requires (os.family != "windows")
 * @library /test/lib
 * @build InterlockTest
 * @run driver/timeout=60 jdk.test.lib.crac.CracTest NativePRNGNonBlocking
 */
/*
 * @test id=NativePRNG
 * @summary Verify that NativePRNG secure random is not interlocked during checkpoint/restore.
 * @requires (os.family != "windows")
 * @library /test/lib
 * @build InterlockTest
 * @run driver/timeout=60 jdk.test.lib.crac.CracTest NativePRNG
 */

/* NativePRNGBlocking is excluded as on some machines /dev/random is exhausted
 * too soon, making the test running too long. */

public class InterlockTest implements Resource, CracTest {
    private static final long PAUSE_SHORT_MS = Utils.adjustTimeout(25);
    private static final long PAUSE_LONG_MS = 10 * PAUSE_SHORT_MS;

    private volatile boolean stop = false;
    private SecureRandom sr;

    @CracTestArg
    String algName;

    private class TestThread1 extends Thread {
        @Override
        public void run() {
            while (!stop) {
                set();
            }
        }
    }

    private class TestThread2 extends Thread implements Resource {
        private final SecureRandom sr;

        synchronized void set() {
            Diag.nextInt(sr);
        }
        synchronized void clean() {
            Diag.nextInt(sr);
        }

        TestThread2() throws Exception {
            sr = SecureRandom.getInstance(algName);
            Context.getGlobalContext().register(this);
        }

        @Override
        public void run() {
            while (!stop) {
                set();
            }
        }

        @Override
        public void beforeCheckpoint(Context<? extends Resource> context) throws Exception {
            Diag.timed("TestThread2.beforeCheckpoint", Diag.beforeCheckpoint, this::clean);
        }

        @Override
        public void afterRestore(Context<? extends Resource> context) throws Exception {
            Diag.timed("TestThread2.afterRestore", Diag.afterRestore, this::set);
        }
    }

    synchronized void clean() {
        Diag.nextInt(sr);
    }

    synchronized void set() {
        Diag.nextInt(sr);
    }

    @Override
    public void beforeCheckpoint(Context<? extends Resource> context) throws Exception {
        try {
            Diag.timed("InterlockTest.beforeCheckpoint", Diag.beforeCheckpoint, this::clean);
        } catch(Exception e) {
            e.printStackTrace(System.out);
        };
    }

    @Override
    public void afterRestore(Context<? extends Resource> context) throws Exception {
        Diag.timed("InterlockTest.afterRestore", Diag.afterRestore, this::set);
        stop = true;
    }

    @Override
    public void test() throws Exception {
        new CracBuilder().engine(CracEngine.SIMULATE).doCheckpoint();
    }

    @Override
    public void exec() throws Exception {
        // A couple of threads per CPU already contend with the checkpoint; going
        // further only oversubscribes the machine, and since both these threads'
        // monitors and the lock the JDK holds across the checkpoint are unfair,
        // the checkpointing thread can then be starved for minutes (JDK-XXXXXXX).
        final int numThreads = Math.clamp(2L * Runtime.getRuntime().availableProcessors(), 2, 100);
        Diag.start(algName + ", " + numThreads + " threads");

        sr = SecureRandom.getInstance(algName);
        Context.getGlobalContext().register(this);

        try {
            for (int i = 0; i < numThreads; i++) {
                final var thread = (i % 2 == 0) ? new TestThread1(): new TestThread2();
                thread.start();
            }
            Thread.sleep(PAUSE_SHORT_MS);
            set();
            Thread.sleep(PAUSE_SHORT_MS);

            final var hasCheckpointThreadSucceeded = new boolean[1];
            final var checkpointThread = new Thread(Diag.CHECKPOINT_THREAD) {
                public void run() {
                    final long[] before = Diag.contentionCounters();
                    try {
                        CRaCMXBean.getCRaCMXBean().checkpointRestore();
                        hasCheckpointThreadSucceeded[0] = true;
                    } catch (CheckpointException | RestoreException e) {
                        throw new RuntimeException("Checkpoint/restore failed", e);
                    } finally {
                        Diag.reportCheckpointContention(before);
                    }
                }
            };
            checkpointThread.start();
            checkpointThread.join();
            if (!hasCheckpointThreadSucceeded[0]) {
                throw new RuntimeException("Checkpoint thread failed");
            }

            Thread.sleep(PAUSE_LONG_MS);
        } finally {
            stop = true;
        }

        Diag.finish();
    }

    /**
     * Temporary instrumentation for JDK-XXXXXXX: on windows-x64 this test times
     * out without printing anything, so we need to know whether the checkpointing
     * thread is deadlocked or merely starved. Both this test's monitors and
     * sun.security.provider.SecureRandom.objLock are unfair, and the checkpointing
     * thread has to win one race per registered resource against numThreads
     * threads that never leave their loops.
     *
     * Everything is written to System.err and flushed line by line: the driver
     * pumps the child's stderr into its own, which is what ends up in the .jtr.
     */
    private static final class Diag {
        static final String CHECKPOINT_THREAD = "checkpointThread";
        static final Stat beforeCheckpoint = new Stat("beforeCheckpoint");
        static final Stat afterRestore = new Stat("afterRestore");
        static final AtomicInteger interlocked = new AtomicInteger();

        // Dense at first: a healthy run is over in a couple of seconds, so
        // anything slower would miss the checkpoint entirely. Then sparse, to
        // bound the output of a run that hangs until the timeout.
        private static final int DENSE_SAMPLES = 20;
        private static final long DENSE_PERIOD_MS = 250;
        private static final long PERIOD_MS = 5_000;
        // Bounded so that jtreg does not truncate away the late samples, which
        // are the interesting ones when the test hangs until the timeout.
        private static final int MAX_STACK_DUMPS = 20;
        private static final int MAX_STACK_DEPTH = 16;
        private static final long SLOW_NANOS = 100_000_000L; // 100 ms
        // A nextInt() is a digest plus a few µs of lock handling; anything
        // above this waited for the checkpoint to release the PRNG.
        private static final long INTERLOCKED_NANOS = 1_000_000L; // 1 ms
        private static final long T0 = System.nanoTime();

        /**
         * Time spent in resource notifications, i.e. waiting for contended locks.
         * Accumulated in nanoseconds: rounding each notification to milliseconds
         * first would report 51 sub-millisecond waits as a total of 0 ms, which
         * cannot be told apart from no waiting at all.
         */
        private static final class Stat {
            private final String name;
            private final AtomicInteger count = new AtomicInteger();
            private final AtomicLong totalNanos = new AtomicLong();
            private final AtomicLong maxNanos = new AtomicLong();

            Stat(String name) {
                this.name = name;
            }

            void add(long nanos) {
                count.incrementAndGet();
                totalNanos.addAndGet(nanos);
                maxNanos.accumulateAndGet(nanos, Math::max);
            }

            @Override
            public String toString() {
                return String.format("%s=%d in %.3f ms (max %.3f ms)",
                        name, count.get(), totalNanos.get() / 1e6, maxNanos.get() / 1e6);
            }
        }

        private static void log(String format, Object... args) {
            System.err.printf("[diag %8.3fs] %s%n",
                    (System.nanoTime() - T0) / 1e9, String.format(format, args));
            System.err.flush();
        }

        /** Reports how long a resource notification had to wait for its lock. */
        static void timed(String what, Stat stat, Runnable body) {
            final long t0 = System.nanoTime();
            body.run();
            final long nanos = System.nanoTime() - t0;
            stat.add(nanos);
            if (nanos >= SLOW_NANOS) {
                log("%s #%d took %.3f ms", what, stat.count.get(), nanos / 1e6);
            }
        }

        /**
         * Every nextInt() in this test goes through here so we can count how
         * often one was interlocked, i.e. blocked on the lock the JDK holds
         * across the checkpoint. This is the coverage number: if it is zero the
         * checkpoint never overlapped with a caller and the test degenerated
         * into an ordering-only check.
         *
         * Deliberately wraps only the PRNG call and not the caller's
         * synchronized method: waiting for the test's own monitor is ordinary
         * contention between workers and has nothing to do with the interlock.
         */
        /** {blockedCount, waitedCount} of the current thread. */
        static long[] contentionCounters() {
            final ThreadInfo info = ManagementFactory.getThreadMXBean()
                    .getThreadInfo(Thread.currentThread().threadId(), 0);
            return info == null ? new long[] {0, 0}
                    : new long[] {info.getBlockedCount(), info.getWaitedCount()};
        }

        /**
         * How often the checkpointing thread itself had to wait during C/R:
         * blocked = entering a monitor another thread held (this test's own),
         * waited = parked, which is where the JDK's PRNG lock shows up.
         * Zero means it walked past every lock uncontended.
         */
        static void reportCheckpointContention(long[] before) {
            final long[] after = contentionCounters();
            log("checkpointThread contention: blocked +%d waited +%d",
                    after[0] - before[0], after[1] - before[1]);
        }

        static void nextInt(SecureRandom sr) {
            final long t0 = System.nanoTime();
            sr.nextInt();
            if (System.nanoTime() - t0 >= INTERLOCKED_NANOS) {
                interlocked.incrementAndGet();
            }
        }

        static void start(String what) {
            log("%s, %d cpus, %s %s", what, Runtime.getRuntime().availableProcessors(),
                    System.getProperty("os.name"), System.getProperty("os.arch"));
            // Must be heard on a saturated machine, hence the priority.
            Thread watchdog = new Thread(Diag::loop, "diag-watchdog");
            watchdog.setDaemon(true);
            watchdog.setPriority(Thread.MAX_PRIORITY);
            watchdog.start();
        }

        static void finish() {
            log("exec() done: %s | %s | interlockedWorkerCalls=%d",
                    beforeCheckpoint, afterRestore, interlocked.get());
            // TEMPORARY: fail on every platform so that CI keeps the .jtr and the
            // windows-x64 output can be compared against the passing platforms.
            throw new RuntimeException("Intentional failure to collect diagnostics");
        }

        private static void loop() {
            final ThreadMXBean tmx = ManagementFactory.getThreadMXBean();
            final boolean cpuTime = tmx.isThreadCpuTimeSupported() && tmx.isThreadCpuTimeEnabled();
            final boolean fullInfo =
                    tmx.isObjectMonitorUsageSupported() && tmx.isSynchronizerUsageSupported();
            String prevStackHead = "";
            int stackDumps = 0;

            for (int sample = 0; ; sample++) {
                try {
                    Thread.sleep(sample < DENSE_SAMPLES ? DENSE_PERIOD_MS : PERIOD_MS);
                } catch (InterruptedException e) {
                    return;
                }
                // Never let the watchdog die: its output is the whole point.
                try {
                    long now = System.nanoTime();

                    // Thread states tell running (starved) from blocked
                    // (deadlocked), and the count drops once workers see 'stop'.
                    long checkpointThreadId = -1;
                    long cpuNanos = 0;
                    // Not ids.length: a thread may die between getAllThreadIds()
                    // and getThreadInfo(), which then returns null for it, and
                    // counting those would report workers that are already gone.
                    int alive = 0;
                    Map<String, Integer> states = new TreeMap<>();
                    Map<String, Integer> lockedOn = new TreeMap<>();
                    long[] ids = tmx.getAllThreadIds();
                    for (ThreadInfo each : tmx.getThreadInfo(ids, 0)) {
                        if (each == null) {
                            continue;
                        }
                        alive++;
                        if (CHECKPOINT_THREAD.equals(each.getThreadName())) {
                            checkpointThreadId = each.getThreadId();
                        }
                        states.merge(each.getThreadState().toString(), 1, Integer::sum);
                        if (each.getLockName() != null) {
                            // Drop the identity hash to aggregate per lock class.
                            lockedOn.merge(each.getLockName().replaceAll("@.*", ""),
                                    1, Integer::sum);
                        }
                    }
                    if (cpuTime) {
                        for (long id : ids) {
                            cpuNanos += Math.max(0, tmx.getThreadCpuTime(id));
                        }
                    }
                    log("---- threads=%d states=%s lockedOn=%s", alive, states, lockedOn);
                    // Only counts threads alive now, so it drops once the workers
                    // exit. Approaching the CPU count means the machine is
                    // saturated and anything rescheduled to take a lock suffers.
                    final long wallNanos = now - T0;
                    log("     liveThreadCpu=%d ms wall=%d ms (%.1f cores) | %s | %s"
                                    + " | interlockedWorkerCalls=%d",
                            cpuNanos / 1_000_000, wallNanos / 1_000_000,
                            wallNanos == 0 ? 0 : (double) cpuNanos / wallNanos,
                            beforeCheckpoint, afterRestore, interlocked.get());

                    long[] deadlocked = fullInfo
                            ? tmx.findDeadlockedThreads() : tmx.findMonitorDeadlockedThreads();
                    if (deadlocked != null) {
                        log("     DEADLOCK %s", Arrays.toString(deadlocked));
                        for (ThreadInfo each : fullInfo
                                ? tmx.getThreadInfo(deadlocked, true, true)
                                : tmx.getThreadInfo(deadlocked, Integer.MAX_VALUE)) {
                            if (each != null) {
                                log("     %s", each);
                            }
                        }
                    }

                    ThreadInfo info = checkpointThreadId < 0 ? null
                            : tmx.getThreadInfo(checkpointThreadId, MAX_STACK_DEPTH);
                    if (info != null) {
                        log("     %s state=%s cpu=%d ms blocked=%d waited=%d lock=%s owner=%s",
                                CHECKPOINT_THREAD, info.getThreadState(),
                                cpuTime ? tmx.getThreadCpuTime(checkpointThreadId) / 1_000_000 : -1,
                                info.getBlockedCount(), info.getWaitedCount(),
                                info.getLockName(), info.getLockOwnerName());

                        // Only when it moved, so that a hang stays cheap to log.
                        StackTraceElement[] stack = info.getStackTrace();
                        String head = Arrays.toString(
                                Arrays.copyOf(stack, Math.min(3, stack.length)));
                        if (!head.equals(prevStackHead) && stackDumps < MAX_STACK_DUMPS) {
                            prevStackHead = head;
                            stackDumps++;
                            for (StackTraceElement element : stack) {
                                log("        at %s", element);
                            }
                        }
                    }
                } catch (Throwable t) {
                    log("watchdog failed: %s", t);
                }
            }
        }
    }
}
