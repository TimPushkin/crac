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
 * @run driver/timeout=60 jdk.test.lib.crac.CracTest SHA1PRNG 100
 */
/*
 * @test id=NativePRNGNonBlocking
 * @summary Verify that NativePRNGNonBlocking secure random is not interlocked during checkpoint/restore.
 * @requires (os.family != "windows")
 * @library /test/lib
 * @build InterlockTest
 * @run driver/timeout=60 jdk.test.lib.crac.CracTest NativePRNGNonBlocking 100
 */
/*
 * @test id=NativePRNG
 * @summary Verify that NativePRNG secure random is not interlocked during checkpoint/restore.
 * @requires (os.family != "windows")
 * @library /test/lib
 * @build InterlockTest
 * @run driver/timeout=60 jdk.test.lib.crac.CracTest NativePRNG 100
 */

/* NativePRNGBlocking is excluded as on some machines /dev/random is exhausted
 * too soon, making the test running too long. */

public class InterlockTest implements Resource, CracTest {
    private static final long MIN_TIMEOUT = 100;
    private static final long MAX_TIMEOUT = 1000;

    private boolean stop = false;
    private SecureRandom sr;

    @CracTestArg(0)
    String algName;

    @CracTestArg(1)
    int numThreads;

    private class TestThread1 extends Thread {
        @Override
        public void run() {
            while (!stop) {
                set();
            }
        }
    };

    private class TestThread2 extends Thread implements Resource {
        private final SecureRandom sr;

        synchronized void set() {
            sr.nextInt();
        }
        synchronized void clean() {
            sr.nextInt();
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
    };

    synchronized void clean() {
        sr.nextInt();
    }

    synchronized void set() {
        sr.nextInt();
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
        Diag.start(algName + ", " + numThreads + " threads");

        sr = SecureRandom.getInstance(algName);
        Context.getGlobalContext().register(this);

        Thread[] threads = new Thread[numThreads];
        for(int i = 0; i < numThreads; i++) {
            threads[i] = (i % 2 == 0) ?
                    new TestThread1():
                    new TestThread2();
            threads[i].start();
        };
        Thread.sleep(MIN_TIMEOUT);
        set();
        Thread.sleep(MIN_TIMEOUT);

        Object checkpointLock = new Object();
        Thread checkpointThread = new Thread(Diag.CHECKPOINT_THREAD) {
            public void run() {
                synchronized (checkpointLock) {
                    try {
                        CRaCMXBean.getCRaCMXBean().checkpointRestore();
                    } catch (CheckpointException e) {
                        throw new RuntimeException("Checkpoint ERROR " + e);
                    } catch (RestoreException e) {
                        throw new RuntimeException("Restore ERROR " + e);
                    }
                    checkpointLock.notify();
                }
            }
        };
        synchronized (checkpointLock) {
            try {
                checkpointThread.start();
                checkpointLock.wait(MAX_TIMEOUT * 2);
            } catch(Exception e){
                throw new RuntimeException("Checkpoint/Restore ERROR " + e);
            }
        }
        Thread.sleep(MAX_TIMEOUT);

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

        // Dense at first to cover the checkpoint itself even on platforms where
        // the test completes in a few seconds, then sparse to bound the output
        // of a run that hangs until the timeout.
        private static final int DENSE_SAMPLES = 10;
        private static final long DENSE_PERIOD_MS = 1_000;
        private static final long PERIOD_MS = 5_000;
        // Bounded so that jtreg does not truncate away the late samples, which
        // are the interesting ones when the test hangs until the timeout.
        private static final int MAX_STACK_DUMPS = 20;
        private static final int MAX_STACK_DEPTH = 16;
        private static final int SLOW_MS = 100;
        private static final long T0 = System.nanoTime();

        /** Time spent in resource notifications, i.e. waiting for contended locks. */
        private static final class Stat {
            private final String name;
            private final AtomicInteger count = new AtomicInteger();
            private final AtomicLong totalMs = new AtomicLong();
            private final AtomicLong maxMs = new AtomicLong();

            Stat(String name) {
                this.name = name;
            }

            void add(long ms) {
                count.incrementAndGet();
                totalMs.addAndGet(ms);
                maxMs.accumulateAndGet(ms, Math::max);
            }

            @Override
            public String toString() {
                return String.format("%s=%d in %d ms (max %d ms)",
                        name, count.get(), totalMs.get(), maxMs.get());
            }
        }

        private static void log(String format, Object... args) {
            System.err.printf("[diag %8.3fs] %s%n",
                    (System.nanoTime() - T0) / 1e9, String.format(format, args));
            System.err.flush();
        }

        /** Reports how long a resource notification had to wait for its lock. */
        static void timed(String what, Stat stat, Runnable body) {
            long t0 = System.nanoTime();
            body.run();
            long ms = (System.nanoTime() - t0) / 1_000_000;
            stat.add(ms);
            if (ms >= SLOW_MS) {
                log("%s #%d took %d ms", what, stat.count.get(), ms);
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
            log("exec() done: %s | %s", beforeCheckpoint, afterRestore);
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
                    Map<String, Integer> states = new TreeMap<>();
                    Map<String, Integer> lockedOn = new TreeMap<>();
                    long[] ids = tmx.getAllThreadIds();
                    for (ThreadInfo each : tmx.getThreadInfo(ids, 0)) {
                        if (each == null) {
                            continue;
                        }
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
                    log("---- threads=%d states=%s lockedOn=%s", ids.length, states, lockedOn);
                    // Only counts threads alive now, so it drops once the workers
                    // exit. liveThreadCpu >> wall * cpus means the machine is
                    // saturated and anything rescheduled to take a lock suffers.
                    log("     cpus=%d liveThreadCpu=%d ms wall=%d ms | %s | %s",
                            Runtime.getRuntime().availableProcessors(),
                            cpuNanos / 1_000_000, (now - T0) / 1_000_000,
                            beforeCheckpoint, afterRestore);

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
