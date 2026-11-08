// D-SfT Tool - automated self test (--selftest, offscreen).
// Verifies every "what if" scenario: deep folder recursion, exec detection,
// create/delete detection, multi-level script chains, sandbox enforcement
// (including child-process bypass), orphan-after-exit-0, stdin feeding,
// .desktop parsing (flatpak wrappers + actions) and end-to-end desktop runs.
#include "mainwindow.h"
#include "desktopentry.h"

#include <QApplication>
#include <QCoreApplication>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QThread>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QTreeWidgetItem>
#include <QPixmap>
#include <cstdio>
#include <functional>

namespace DSfT {

static int g_fail = 0;

static void check(bool ok, const QString& what)
{
    printf("%s  %s\n", ok ? "PASS" : "FAIL", what.toUtf8().constData());
    fflush(stdout);
    if (!ok) ++g_fail;
}

static bool waitUntil(const std::function<bool()>& pred, int ms)
{
    QElapsedTimer t;
    t.start();
    while (t.elapsed() < ms) {
        // pump FIRST so queued QProcess/QLocalSocket signals are delivered
        // before the predicate is (re)checked — otherwise a fast-exiting
        // process looks "finished" with none of its output processed.
        QCoreApplication::processEvents(QEventLoop::AllEvents, 25);
        if (pred()) return true;
        QThread::msleep(15);
    }
    QCoreApplication::processEvents(QEventLoop::AllEvents, 100);
    return pred();
}

static QTreeWidgetItem* findItem(QTreeWidgetItem* parent, const QString& text)
{
    if (!parent) return nullptr;
    if (parent->text(0) == text) return parent;
    for (int i = 0; i < parent->childCount(); ++i) {
        QTreeWidgetItem* r = findItem(parent->child(i), text);
        if (r) return r;
    }
    return nullptr;
}

static bool activityHas(const MainWindow& w, const QString& a, const QString& b = QString())
{
    for (const QString& l : w.activityLog())
        if (l.contains(a) && (b.isEmpty() || l.contains(b))) return true;
    return false;
}

static void chmodExec(const QString& path)
{
    QFile::setPermissions(path,
        QFile::ReadOwner | QFile::WriteOwner | QFile::ExeOwner |
        QFile::ReadGroup | QFile::ExeGroup | QFile::ReadOther | QFile::ExeOther);
}

static QString copyExe(const QString& src, const QString& dst)
{
    QFile::remove(dst);
    QFile::copy(src, dst);
    chmodExec(dst);
    return dst;
}

// finish a run started with args, wait for exit (and for its exit line,
// i.e. the finished() signal has actually been delivered and processed)
static void runAndWait(MainWindow& w, const QString& path, const QString& args = QString(),
                       const QString& actionExec = QString())
{
    w.prepareForTest();
    w.runPath(path, args, actionExec);
    waitUntil([&w]() { return !w.isRunning() && !w.lastExitLine().isEmpty(); }, 20000);
}

int runSelfTest()
{
    const QString build = QCoreApplication::applicationDirPath();
    const QString td = build + "/testdata";
    const QString bin = td + "/bin";

    printf("== D-SfT Tool self test ==\n"
           "build dir: %s\n", build.toUtf8().constData());

    // ---- sandbox work area ----
    const QString tmp = QString("/tmp/dsft-selftest-%1").arg(QCoreApplication::applicationPid());
    QDir().mkpath(tmp + "/folderB/deep/deeper/deepest");
    copyExe(bin + "/hello", tmp + "/A.exe");
    copyExe(bin + "/writer", tmp + "/folderB/B.exe");
    copyExe(bin + "/hello", tmp + "/folderB/deep/deeper/deepest/hidden.exe");
    // non-runnable files with REAL magic bytes (mime detection is content-based)
    { QFile f(tmp + "/pic.png"); f.open(QIODevice::WriteOnly);
      f.write("\x89PNG\r\n\x1a\n" + QByteArray(64, 'x')); }
    { QFile f(tmp + "/clip.mp4"); f.open(QIODevice::WriteOnly);
      f.write(QByteArray("\x00\x00\x00\x18ftypmp42\x00\x00\x00", 16) + QByteArray(64, 'x')); }
    for (const QString& s : {"chainA.sh", "chainB.sh", "chainC.sh"})
        chmodExec(td + "/scripts/" + s);

    MainWindow w;
    w.resize(1240, 780);
    w.show();
    QCoreApplication::processEvents();

    // hermetic start: drop anything restored from data/config.json
    w.tree()->clear();
    w.m_limits.clear();

    // ================================================== 1. desktop parsing
    {
        const DesktopEntry e = parseDesktopFile(td + "/desktop/sample.desktop");
        const QStringList toks = e.execTokens("");
        check(e.valid, "desktop: sample.desktop parses");
        check(toks.value(0) == "/usr/bin/flatpak", "desktop: program is /usr/bin/flatpak");
        check(!toks.contains("@@u") && !toks.contains("%u") && !toks.contains("@@"),
              "desktop: flatpak @@u %u @@ wrapper stripped");
        check(toks.last() == "--", "desktop: trailing -- kept");
        check(e.actions.size() == 1 && e.actions.first().id == "open-settings",
              "desktop: [Desktop Action open-settings] found");
        const DesktopEntry::Action a = e.actions.first();
        QStringList t2;
        {
            DesktopEntry tmp2 = e;
            tmp2.execLine = a.execLine;
            t2 = tmp2.execTokens("");
        }
        check(t2.last() == "config", "desktop: action Exec ends with 'config'");
        // arg substitution: %u style code replaced by user arg
        DesktopEntry e2;
        e2.execLine = "/usr/bin/flatpak run --command=sober org.vinegarhq.Sober -- @@u %u @@";
        const QStringList sub = e2.execTokens("save.roblox");
        check(sub.contains("save.roblox"), "desktop: file/url code substituted with args");
    }

    // ================================================== 2. deep folder tree
    {
        check(w.addPathToTree(tmp), "tree: root folder added");
        // expand the whole chain lazily (arrow -> children of children...)
        QTreeWidgetItem* top = w.tree()->topLevelItem(0);
        QList<QTreeWidgetItem*> stack{top};
        while (!stack.isEmpty()) {
            QTreeWidgetItem* cur = stack.takeFirst();
            cur->setExpanded(true);                       // triggers lazy populate
            for (int i = 0; i < cur->childCount(); ++i) stack.append(cur->child(i));
        }
        QCoreApplication::processEvents();
        QTreeWidgetItem* hidden = findItem(top, "hidden.exe");
        check(hidden != nullptr,
              "tree: child-of-child-of-child exe appears WITHOUT re-adding folders");
        QTreeWidgetItem* b = findItem(top, "B.exe");
        check(b != nullptr, "tree: nested folder exe listed");
        QTreeWidgetItem* a = findItem(top, "A.exe");
        check(a != nullptr, "tree: root-level exe listed");
        // non-runnable files are SHOWN (muted) with content-type icons
        QTreeWidgetItem* pic = findItem(top, "pic.png");
        check(pic != nullptr && !pic->icon(0).isNull() && !pic->data(0, Qt::UserRole + 1).toBool(),
              "tree: .png shown muted + not runnable, with its own image icon");
        QTreeWidgetItem* clip = findItem(top, "clip.mp4");
        check(clip != nullptr && !clip->icon(0).isNull() && !clip->data(0, Qt::UserRole + 1).toBool(),
              "tree: .mp4 detected by CONTENT (magic bytes) with its video icon");
        QFile::remove(tmp + "/A.exe");   // tidy up for later blocks
    }

    // ================================================== 3. hello (stdout)
    {
        runAndWait(w, bin + "/hello");
        check(w.plainOut().contains("hi"), "output: std::cout-style 'hi' captured");
        check(w.lastExitLine() == "exit code 0", "output: exit code 0 reported");
    }

    // ================================================== 4. create/delete detection
    {
        const QString victim = tmp + "/victim.txt";
        QFile::remove(victim);
        runAndWait(w, bin + "/remover", victim);
        check(waitUntil([&w, victim]() { return activityHas(w, "create", victim); }, 3000),
              "activity: file CREATE detected (yellow line)");
        check(waitUntil([&w, victim]() { return activityHas(w, "rm", victim); }, 3000),
              "activity: file REMOVE detected (yellow line)");
        if (g_fail) {
            printf("---- activity dump (remover run) ----\n");
            for (const QString& l : w.activityLog())
                printf("  | %s\n", l.toUtf8().constData());
        }
        check(!QFile::exists(victim), "activity: remover really deleted its file");
    }

    // ================================================== 5. exec detection (cmd run)
    {
        runAndWait(w, td + "/scripts/chainA.sh");
        bool b = false, c = false;
        for (const QString& l : w.activityLog()) {
            if (l.contains(": run") && l.contains("chainB.sh")) b = true;
            if (l.contains(": run") && l.contains("chainC.sh")) c = true;
        }
        check(b, "activity: script->script exec detected (level 2)");
        check(c, "activity: script->script->script exec detected (level 3)");
        check(w.plainOut().contains("chain C (level 3)"), "output: chained script output shown");
    }

    // ================================================== 6. stop kills the whole chain
    {
        w.prepareForTest();
        w.runPath(td + "/scripts/chainA.sh");
        waitUntil([&w]() { return w.plainOut().contains("chain C (level 3)"); }, 8000);
        w.stopRun();
        waitUntil([&w]() { return !w.isRunning() && !w.lastExitLine().isEmpty(); }, 10000);
        const bool allDead = waitUntil([&w]() {
            for (auto it = w.m_registry.begin(); it != w.m_registry.end(); ++it) {
                pid_t p = (pid_t)it.key();
                if (MainWindow::procAlive(p)) return false;   // zombie counts as dead
            }
            return true;
        }, 4000);
        check(allDead, "stop: every script level + background child is dead");
    }

    // ================================================== 7. sandbox: own writes over limit
    {
        const QString out = tmp + "/big.bin";
        QFile::remove(out);
        w.setQuotaFor(bin + "/writer", 10);           // 10 MB limit
        runAndWait(w, bin + "/writer", QString("%1 100").arg(out));
        check(waitUntil([&w]() { return w.hasQuotaHit(); }, 5000),
              "sandbox: quota hit detected while writing 100 MB");
        check(waitUntil([&out]() { return !QFile::exists(out); }, 5000),
              "sandbox: partially-written file DELETED");
        check(waitUntil([&w]() { return activityHas(w, "DISK QUOTA EXCEEDED"); }, 3000),
              "sandbox: quota termination logged in yellow");
        if (g_fail) {
            printf("---- activity dump (writer run) ----\n");
            for (const QString& l : w.activityLog())
                printf("  | %s\n", l.toUtf8().constData());
            printf("  writtenBytes=%lld quotaHit=%d exit=%s fileExists=%d\n",
                   (long long)w.m_writtenBytes, (int)w.hasQuotaHit(),
                   w.lastExitLine().toUtf8().constData(), (int)QFile::exists(out));
        }
    }

    // ================================================== 8. sandbox bypass via another program
    {
        const QString out = tmp + "/bypass.bin";
        QFile::remove(out);
        w.setQuotaFor(bin + "/bypass", 10);
        runAndWait(w, bin + "/bypass", out);
        check(waitUntil([&w]() { return w.hasQuotaHit(); }, 5000),
              "sandbox: bypass via fork+exec'd dd is CAUGHT");
        check(waitUntil([&out]() { return !QFile::exists(out); }, 5000),
              "sandbox: dd's partial output deleted");
        check(waitUntil([&w]() {
                  for (auto it = w.m_registry.begin(); it != w.m_registry.end(); ++it)
                      if (it.value().comm == "dd" && MainWindow::procAlive((pid_t)it.key()))
                          return false;
                  return true;
              }, 5000),
              "sandbox: the exec'd child (dd) was terminated too");
    }

    // ================================================== 8b. CONTAINMENT: whole tree dies
    {
        const QString out = tmp + "/child.bin";
        QFile::remove(out);
        w.setQuotaFor(bin + "/quotachild", 10);
        runAndWait(w, bin + "/quotachild", out);
        check(w.hasQuotaHit(), "sandbox: child process over quota is detected");
        check(w.m_peakWritten > 0, "sandbox: disk-written meter counted LIVE during the run");
        check(waitUntil([&out]() { return !QFile::exists(out); }, 5000),
              "sandbox: over-quota file DELETED (space freed)");
        check(w.lastExitLine().contains("terminated by sandbox"),
              "sandbox: the launched app is terminated when the tree passes the limit");
        const bool treeDead = waitUntil([&w]() {
            for (auto it = w.m_registry.begin(); it != w.m_registry.end(); ++it)
                if (MainWindow::procAlive((pid_t)it.key())) return false;
            return true;
        }, 4000);
        check(treeDead, "sandbox: EVERYTHING it ran is dead too (parent, children, grandchildren)");
    }

    // ================================================== 8c. the user's real scenario:
    // two 45 MB copies inside one bash, limit 90 MB -> the tree is terminated
    // exactly AT the limit, everything it copied is deleted, nothing survives.
    {
        QFile::remove(tmp + "/big45.bin");
        {
            QFile big(tmp + "/big45.bin");
            big.open(QIODevice::WriteOnly);
            const QByteArray chunk(1024 * 1024, '\0');
            for (int i = 0; i < 45; ++i) big.write(chunk);   // 45 MB
            big.close();
        }
        QFile script(tmp + "/twocopies.sh");
        script.open(QIODevice::WriteOnly | QIODevice::Truncate);
        script.write(QString("#!/bin/sh\ncp %1 copyA.bin\ncp %1 copyB.bin\necho script-done\n")
                         .arg(tmp + "/big45.bin").toUtf8());
        script.close();
        QFile::remove(tmp + "/copyA.bin");
        QFile::remove(tmp + "/copyB.bin");
        chmodExec(tmp + "/twocopies.sh");

        const QString scriptPath = tmp + "/twocopies.sh";
        w.setQuotaFor(canonical(scriptPath), 90);
        runAndWait(w, scriptPath);
        check(w.hasQuotaHit(), "scenario: 45+45 MB hits the 90 MB limit");
        check(w.lastExitLine().contains("terminated by sandbox"),
              "scenario: the whole program tree is terminated (virus containment)");
        check(waitUntil([&tmp]() { return !QFile::exists(tmp + "/copyA.bin"); }, 5000) &&
              !QFile::exists(tmp + "/copyB.bin"),
              "scenario: EVERYTHING it created is deleted (copyA + copyB gone)");
        const bool treeDead = waitUntil([&w]() {
            for (auto it = w.m_registry.begin(); it != w.m_registry.end(); ++it)
                if (MainWindow::procAlive((pid_t)it.key())) return false;
            return true;
        }, 4000);
        check(treeDead, "scenario: bash + both cp processes all dead");
        QFile::remove(tmp + "/big45.bin");
    }

    // ================================================== 8d. mass mkdir (dir accounting + speed)
    {
        QDir().mkpath(tmp + "/mass");
        w.setQuotaFor(bin + "/massmkdir", 10);        // 10 MB ≈ 2560 dirs
        runAndWait(w, bin + "/massmkdir", tmp + "/mass 5000");
        check(w.hasQuotaHit(), "massmkdir: 5000 dirs (~20 MB) hit the 10 MB limit");
        check(w.lastExitLine().contains("terminated by sandbox"),
              "massmkdir: terminated when dirs alone exceed the limit");
        check(w.m_peakWritten > 0, "massmkdir: meter counted directory blocks LIVE");
        const int left = QDir(tmp + "/mass").entryList(QDir::Dirs | QDir::NoDotAndDotDot).size();
        check(left < 5000, QString("massmkdir: mass-created dirs cleaned up (%d left)").arg(left));
        QDir(tmp + "/mass").removeRecursively();
    }

    // ================================================== 8e. RAM limit — terminate
    {
        w.setLimitsFor(bin + "/rameater", Limits());
        Limits l = w.m_limits.value(bin + "/rameater");
        l.ramMB = 10; l.ramTerminate = true;
        w.setLimitsFor(bin + "/rameater", l);
        runAndWait(w, bin + "/rameater", "100");
        check(w.plainOut().contains("RAM LIMIT EXCEEDED"),
              "ram: 100 MB rameater hits the 10 MB RAM limit");
        check(w.lastExitLine().contains("terminated by sandbox"),
              "ram: the tree is terminated (terminate mode)");
        check(w.peakRam() > 0, "ram: RAM meter counted live");
        const bool dead = waitUntil([&w]() {
            for (auto it = w.m_registry.begin(); it != w.m_registry.end(); ++it)
                if (MainWindow::procAlive((pid_t)it.key())) return false;
            return true;
        }, 4000);
        check(dead, "ram: whole tree dead");
    }

    // ================================================== 8f. own-ram jail — NOT terminated, but jailed
    {
        Limits l = w.m_limits.value(bin + "/rameater");
        l.ramMB = 10; l.ramTerminate = false; l.ramOwn = true;
        w.setLimitsFor(bin + "/rameater", l);
        runAndWait(w, bin + "/rameater", "100");
        check(w.plainOut().contains("alloc-failed"),
              "ram jail: allocations FAIL beyond the limit (app glitches, not killed)");
        check(w.lastExitLine() == "exit code 3",
              "ram jail: the app exits ON ITS OWN (exit code 3), not terminated");
        check(!w.lastExitLine().contains("terminated by sandbox"),
              "ram jail: sandbox did NOT terminate anything");
    }

    // ================================================== 8f2. own-ram jail vs RAW
    // mmap — the bypass that proved the old LD_PRELOAD jail fake. mmeater
    // never calls malloc, so ONLY the kernel can stop it: under the jail it
    // must not get to eat 50 MB (OOM-killed inside the scope, or mmap fails
    // on the RLIMIT_AS fallback) and the RSS meter must stay at the ceiling.
    {
        Limits l = w.m_limits.value(bin + "/mmeater");
        l.ramMB = 10; l.ramTerminate = false; l.ramOwn = true;
        w.setLimitsFor(bin + "/mmeater", l);
        runAndWait(w, bin + "/mmeater", "50");
        check(activityHas(w, "KERNEL JAIL") || activityHas(w, "kernel jail UNAVAILABLE"),
              "ram jail: jail mode announced (kernel scope, or loud RLIMIT_AS fallback)");
        check(!w.plainOut().contains("JAIL DID NOT STOP IT"),
              "ram jail: raw-mmap mmeater 50 does NOT get to eat its 50 MB");
        check(w.peakRam() <= (10 + 4) * 1024 * 1024,
              QString("ram jail: RSS stayed at the kernel ceiling (peak %1 MB ≤ ~14 MB)")
                  .arg(w.peakRam() / (1024 * 1024)));
        check(w.lastExitLine().contains("signal 9") || w.plainOut().contains("mmap FAILED"),
              "ram jail: mmeater died by kernel OOM (or mmap failed) — like a real constrained PC");
        if (g_fail) {
            printf("---- activity dump (mmeater run) ----\n");
            for (const QString& l : w.activityLog())
                printf("  | %s\n", l.toUtf8().constData());
            printf("  peakRam=%lld exit=%s\n", (long long)w.peakRam(),
                   w.lastExitLine().toUtf8().constData());
        }
    }

    // ================================================== 8g. disk: delete WITHOUT terminate
    {
        const QString out = tmp + "/delonly.bin";
        QFile::remove(out);
        Limits l = w.m_limits.value(bin + "/writer");
        l.diskMB = 10; l.diskTerminate = false; l.diskDelete = true;
        w.setLimitsFor(bin + "/writer", l);
        runAndWait(w, bin + "/writer", QString("%1 100").arg(out));
        check(w.hasQuotaHit(), "disk delete-mode: limit hit detected");
        check(!QFile::exists(out), "disk delete-mode: created file deleted instantly");
        check(!w.lastExitLine().contains("terminated by sandbox"),
              "disk delete-mode: program NOT terminated");
        check(w.plainOut().contains("write stopped"),
              "disk delete-mode: writes are BLOCKED (limited) while it runs");
    }

    // ================================================== 8h. CPU limit — terminate
    {
        Limits l = w.m_limits.value(bin + "/cpueater");
        l.cpuPct = 5; l.cpuTerminate = true; l.cpuOwn = false;
        w.setLimitsFor(bin + "/cpueater", l);
        w.prepareForTest();
        w.runPath(bin + "/cpueater", "10");
        const bool killed = waitUntil([&w]() {
            return w.lastExitLine().contains("terminated by sandbox"); }, 15000);
        check(killed, "cpu: 100%-burning cpueater terminated (sustained > 5%)");
        w.stopRun();
        waitUntil([&w]() { return !w.isRunning() && !w.lastExitLine().isEmpty(); }, 5000);
    }

    // ================================================== 8i. own-cpu jail — throttled, survives
    {
        Limits l = w.m_limits.value(bin + "/cpueater");
        l.cpuPct = 6; l.cpuTerminate = false; l.cpuOwn = true;   // 6% of ALL cores < burner's ~1/8 machine
        w.setLimitsFor(bin + "/cpueater", l);
        QElapsedTimer wall;
        wall.start();
        runAndWait(w, bin + "/cpueater", "2");
        check(w.lastExitLine() == "exit code 0",
              "cpu jail: throttled cpueater SURVIVES its full 2 s run (exit 0)");
        check(wall.elapsed() >= 2000, "cpu jail: throttled run took its full wall time");
    }

    // ================================================== 9. orphan after exit code 0
    {
        runAndWait(w, bin + "/orphan");
        check(w.lastExitLine() == "exit code 0", "orphan: parent reported exit code 0");
        const bool detected = waitUntil([&w]() { return w.orphanCount() > 0; }, 8000);
        check(detected, "orphan: leftover child DETECTED after exit code 0");
        const bool killed = waitUntil([&w]() {
            for (auto it = w.m_registry.begin(); it != w.m_registry.end(); ++it)
                if (it.value().comm == "sleep" && MainWindow::procAlive((pid_t)it.key()))
                    return false;
            return true;
        }, 8000);
        check(killed, "orphan: leftover child killed (auto-kill orphans)");
    }

    // ================================================== 10. stdin feeding
    {
        w.prepareForTest();
        w.runPath(bin + "/echoline");
        waitUntil([&w]() { return w.plainOut().contains("What is your name?"); }, 8000);
        const bool asked = waitUntil([&w]() {
            for (const QString& l : w.activityLog())
                if (l.contains("waiting for input")) return true;
            return false;
        }, 4000);
        check(asked, "input: program's stdin read detected + notified");
        w.sendStdin("World");
        waitUntil([&w]() { return w.plainOut().contains("Hello, World!"); }, 8000);
        check(w.plainOut().contains("Hello, World!"), "input: typed stdin reached the program");
        w.stopRun();
        waitUntil([&w]() { return !w.isRunning() && !w.lastExitLine().isEmpty(); }, 5000);
    }

    // ================================================== 11. desktop end-to-end run
    {
        const QString dp = tmp + "/run.desktop";
        QFile f(dp);
        f.open(QIODevice::WriteOnly | QIODevice::Truncate);
        f.write(QString("[Desktop Entry]\nType=Application\nName=Hello Via Desktop\n"
                        "Exec=%1 @@u %%u @@\n\n[Desktop Action greet]\nName=Greet\n"
                        "Exec=%1\n").arg(bin + "/hello").toUtf8());
        f.close();
        runAndWait(w, dp, "extra-arg");
        if (!w.plainOut().contains("hi")) {
            QFile f2(dp);
            f2.open(QIODevice::ReadOnly);
            printf("---- desktop diagnostics ----\n  file: %s\n  exit: %s\n",
                   f2.readAll().constData(), w.lastExitLine().toUtf8().constData());
            DesktopEntry de2 = parseDesktopFile(dp);
            printf("  tokens:");
            for (const QString& t : de2.execTokens("extra-arg")) printf(" [%s]", t.toUtf8().constData());
            printf("\n");
        }
        check(w.plainOut().contains("hi"), "desktop: .desktop Exec (flatpak wrapper) RAN and printed hi");
        check(w.lastExitLine() == "exit code 0", "desktop: desktop-run exit code 0");
        // action variant
        runAndWait(w, dp, QString(), bin + "/hello");
        check(w.plainOut().contains("hi"), "desktop: [Desktop Action] variant runs");
    }

    // ================================================== 12. UI: gray button, clear all, select all
    {
        w.prepareForTest();
        w.tree()->clear();                     // fresh tree for this UI test
        QCoreApplication::processEvents();
        check(!w.m_sandboxBtn->isEnabled(),
              "ui: Limitations button is GRAY with no runnable selected");
        w.addPathToTree(bin + "/hello");
        QCoreApplication::processEvents();
        w.tree()->setCurrentItem(w.tree()->topLevelItem(0));
        QCoreApplication::processEvents();
        check(w.m_sandboxBtn->isEnabled(),
              "ui: Limitations button ENABLED for a runnable selection");
        // Clear all (same action the context menu triggers)
        w.onClearAll();
        check(w.tree()->topLevelItemCount() == 0, "ui: Clear all empties the explorer");
        check(!w.m_sandboxBtn->isEnabled(),
              "ui: Limitations button gray again after Clear all");
        // select-all (the Ctrl+A shortcut calls selectAll on the tree)
        w.addPathToTree(bin + "/hello");
        w.addPathToTree(bin + "/writer");
        w.tree()->selectAll();
        QCoreApplication::processEvents();
        check(w.tree()->selectedItems().size() >= 2, "ui: select-all selects every entry");
        w.onClearAll();
    }

    // ================================================== 12. fuzzy search
    {
        w.prepareForTest();
        // reproduce the user's case: konsole.desktop searched with a typo
        QFile::copy(td + "/desktop/sample.desktop", tmp + "/konsole.desktop");
        w.addPathToTree(tmp + "/konsole.desktop");
        w.addPathToTree(td + "/scripts");
        QCoreApplication::processEvents();
        w.m_searchEdit->setText("kansole");
        QCoreApplication::processEvents();
        QTreeWidgetItem* cur = w.tree()->currentItem();
        check(cur && cur->text(0) == "konsole.desktop",
              "search: typo 'kansole' finds konsole.desktop (auto-selected)");
        // partial search
        w.m_searchEdit->setText("kons");
        QCoreApplication::processEvents();
        bool visible = false;
        for (QTreeWidgetItemIterator it(w.tree()); *it; ++it)
            if ((*it)->text(0) == "konsole.desktop") visible = !(*it)->isHidden();
        check(visible, "search: substring 'kons' matches konsole.desktop");
        // folders match too
        w.m_searchEdit->setText("scripts");
        QCoreApplication::processEvents();
        bool folderHit = false;
        for (QTreeWidgetItemIterator it(w.tree()); *it; ++it)
            if ((*it)->text(0) == "scripts") folderHit = !(*it)->isHidden();
        check(folderHit, "search: folders match as well (scripts)");
        w.m_searchEdit->clear();
        QCoreApplication::processEvents();
        bool allVisible = true;
        for (QTreeWidgetItemIterator it(w.tree()); *it; ++it)
            if ((*it)->isHidden()) allVisible = false;
        check(allVisible, "search: clearing shows everything again");
        QFile::remove(tmp + "/konsole.desktop");
    }

    // ================================================== 14. REAL-WORLD app test: konsole (Qt) via its .desktop
    {
        const QString konsoleDesktop = "/usr/share/applications/org.kde.konsole.desktop";
        if (!QFileInfo::exists(konsoleDesktop)) {
            printf("SKIP  real app: %s not found on this system\n", konsoleDesktop.toUtf8().constData());
        } else {
            w.prepareForTest();
            w.addPathToTree(konsoleDesktop);
            w.runPath(konsoleDesktop);
            const bool started = waitUntil([&w]() { return w.isRunning(); }, 10000);
            check(started, "real app: konsole launched from its .desktop entry");
            QElapsedTimer t;
            t.start();
            waitUntil([&w, &t]() { return !w.isRunning() || t.elapsed() > 2500; }, 8000);
            const bool crashed = w.lastExitLine().contains("signal 11") ||
                                 w.plainOut().contains("KCrash");
            check(started && !crashed && w.isRunning(),
                  "real app: konsole runs 2.5 s WITHOUT crashing (shim is safe for real Qt apps)");
            check(w.peakRam() > 15 * 1024 * 1024,
                  QString("real app: RAM meter is REAL resident memory (konsole RSS = %1 MB)")
                      .arg(w.peakRam() / (1024 * 1024)));
            w.stopRun();
            waitUntil([&w]() { return !w.isRunning() && !w.lastExitLine().isEmpty(); }, 8000);
            const bool dead = waitUntil([&w]() {
                for (auto it = w.m_registry.begin(); it != w.m_registry.end(); ++it)
                    if (MainWindow::procAlive((pid_t)it.key())) return false;
                return true;
            }, 5000);
            check(dead, "real app: stop kills konsole + its whole tree");
        }
    }

    // ================================================== 14b. real app INSIDE the
    // own-ram kernel jail: a generous limit must not break a real Qt app
    {
        const QString konsoleDesktop = "/usr/share/applications/org.kde.konsole.desktop";
        if (!QFileInfo::exists(konsoleDesktop)) {
            printf("SKIP  real app in jail: %s not found on this system\n",
                   konsoleDesktop.toUtf8().constData());
        } else {
            Limits l = w.m_limits.value(canonical(konsoleDesktop));
            l.ramMB = 512; l.ramTerminate = false; l.ramOwn = true;
            w.setLimitsFor(canonical(konsoleDesktop), l);
            w.prepareForTest();
            w.addPathToTree(konsoleDesktop);
            w.runPath(konsoleDesktop);
            const bool started = waitUntil([&w]() { return w.isRunning(); }, 10000);
            check(started, "real app: konsole launched UNDER the 512 MB own-ram kernel jail");
            QElapsedTimer t;
            t.start();
            waitUntil([&w, &t]() { return !w.isRunning() || t.elapsed() > 2500; }, 8000);
            const bool crashed = w.lastExitLine().contains("signal 11") ||
                                 w.plainOut().contains("KCrash");
            check(started && !crashed && w.isRunning(),
                  "real app: konsole runs 2.5 s inside the jail WITHOUT crashing");
            check(w.peakRam() <= 512 * 1024 * 1024,
                  QString("real app: konsole stayed inside the jail (RSS peak = %1 MB)")
                      .arg(w.peakRam() / (1024 * 1024)));
            w.stopRun();
            waitUntil([&w]() { return !w.isRunning() && !w.lastExitLine().isEmpty(); }, 8000);
            const bool dead = waitUntil([&w]() {
                for (auto it = w.m_registry.begin(); it != w.m_registry.end(); ++it)
                    if (MainWindow::procAlive((pid_t)it.key())) return false;
                return true;
            }, 5000);
            check(dead, "real app: stop kills konsole + its tree even inside the jail scope");
            // leave no test jail limits behind in the owner's config
            // (setLimitsFor also refreshes the tree's Limits column)
            w.setLimitsFor(canonical(konsoleDesktop), Limits());
        }
    }

    // ================================================== 15. limitations persistence across restart
    {
        Limits l;
        l.diskMB = 77; l.ramMB = 33; l.cpuPct = 11; l.ramOwn = true;
        w.setLimitsFor(bin + "/hello", l);
        w.saveSettings();
        auto* w2 = new MainWindow;           // fresh window → loads config.json
        const Limits loaded = w2->m_limits.value(canonical(bin + "/hello"));
        check(loaded.diskMB == 77 && loaded.ramMB == 33 && loaded.cpuPct == 11 && loaded.ramOwn,
              "persistence: limitations survive a restart");
        check(!w2->m_sandboxBtn->isEnabled(), "persistence: fresh window, Limitations button gray");
        w2->m_limits.remove(canonical(bin + "/hello"));
        w2->saveSettings();
        delete w2;
    }

    // ================================================== screenshots for visual check
    {
        w.prepareForTest();
        w.addPathToTree(tmp);
        w.addPathToTree(td + "/scripts");
        w.addPathToTree(td + "/desktop");
        w.tree()->expandAll();
        QCoreApplication::processEvents();
        // simulate a session's worth of output for the screenshot
        runAndWait(w, bin + "/remover", tmp + "/victim.txt");
        const QPixmap pm = w.grab();
        pm.save("/home/danhze/Desktop/enviroment/D-SfT-Tool/selftest-ui.png");
        printf("screenshot saved: selftest-ui.png\n");
    }

    QDir(tmp).removeRecursively();
    printf("== done: %d failure(s) ==\n", g_fail);
    return g_fail == 0 ? 0 : 1;
}

} // namespace DSfT
