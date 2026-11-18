// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0

package binaryrat;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

/** Test the installed service queue independently of any native lease timing. */
public final class AdmissionQueueProof {
    private static final class QueuedMonitor extends TaskMonitorAdapter {
        final CountDownLatch queued = new CountDownLatch(1);

        QueuedMonitor() {
            super(true);
        }

        @Override
        public void checkCancelled() throws CancelledException {
            queued.countDown();
            super.checkCancelled();
        }

        void awaitQueue() throws Exception {
            if (!queued.await(2, TimeUnit.SECONDS)) {
                throw new IllegalStateException("Request did not reach the queue");
            }
        }
    }

    public static void main(String[] args) throws Exception {
        try {
            new DecompilationSession.AdmissionQueue(0);
            throw new IllegalStateException("A queue with no worker accepted requests");
        }
        catch (IllegalArgumentException expected) {
            // A budget that admits no workers must fail instead of blocking requests.
        }
        for (int index = 0; index < 12; index++) {
            proveQueue();
        }
        System.out.println("BINARYRAT_ADMISSION_QUEUE_OK");
    }

    private static void proveQueue() throws Exception {
        var queue = new DecompilationSession.AdmissionQueue(1);
        List<String> order = Collections.synchronizedList(new ArrayList<>());
        queue.enter(false, TaskMonitor.DUMMY);
        var workers = Executors.newFixedThreadPool(3);
        try {
            var batch = new QueuedMonitor();
            var foreground = new QueuedMonitor();
            var cancelled = new QueuedMonitor();
            var batchTask = workers.submit(() -> enter(queue, batch, false, order, "batch"));
            batch.awaitQueue();
            var cancelledTask = workers.submit(() ->
                enter(queue, cancelled, true, order, "cancelled"));
            cancelled.awaitQueue();
            var foregroundTask = workers.submit(() ->
                enter(queue, foreground, true, order, "foreground"));
            foreground.awaitQueue();
            cancelled.cancel();
            if (cancelledTask.get(2, TimeUnit.SECONDS)) {
                throw new IllegalStateException("Cancelled foreground request entered");
            }
            if (!order.isEmpty()) {
                throw new IllegalStateException("The active slot was preempted");
            }
            queue.leave();
            if (!foregroundTask.get(2, TimeUnit.SECONDS) || !batchTask.get(2, TimeUnit.SECONDS) ||
                    !order.equals(List.of("foreground", "batch"))) {
                throw new IllegalStateException("Unexpected admission order: " + order);
            }
        }
        finally {
            workers.shutdownNow();
            if (!workers.awaitTermination(2, TimeUnit.SECONDS)) {
                throw new IllegalStateException("Admission waiters did not terminate");
            }
        }
    }

    private static boolean enter(DecompilationSession.AdmissionQueue queue, TaskMonitor monitor,
            boolean foreground, List<String> order, String value) {
        try {
            queue.enter(foreground, monitor);
        }
        catch (CancelledException cancelled) {
            return false;
        }
        try {
            order.add(value);
            return true;
        }
        finally {
            queue.leave();
        }
    }
}
