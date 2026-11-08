// D-SfT Tool - runner: launching programs, shim event stream, kill-tree,
// disk-quota sandbox enforcement, orphan (exit-0-but-still-running) handling.
#include "mainwindow.h"
#include "desktopentry.h"
#include "shim/shim_layout.h"

#include <QFileInfo>
#include <QDir>
#include <QFile>
#include <QSet>
#include <QScrollBar>
#include <QDateTime>
#include <QStyle>
#include <QSocketNotifier>
#include <utility>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/resource.h>
#include <errno.h>

// ------------------------------------------------------------------ helpers
static QString readTextFile(const QString& path, qint64 max = 256)
{
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly)) return QString();
    return QString::fromLocal8Bit(f.read(max)).trimmed();
}

bool MainWindow::procAlive(pid_t pid)
{
    if (pid <= 0) return false;
    const QString stat = readTextFile(QString("/proc/%1/stat").arg(pid), 512);
    if (stat.isEmpty()) return false;
    const int rp = stat.lastIndexOf(')');
    if (rp < 0 || rp + 2 >= stat.size()) return true;    // can't parse: assume alive
    const QChar state = stat.mid(rp + 2, 1).at(0);
    return state != 'Z';
}

// ------------------------------------------------- own-ram kernel jail (cgroup v2)
// "Own ram sandbox?" must be a REAL jail: the process runs as if on a PC that
// only HAS <N> MB of RAM. An LD_PRELOAD shim can only filter malloc — raw
// mmap, glibc-internal allocations and static binaries bypass it. So the jail
// is enforced by the KERNEL via a cgroup v2 scope in the user's systemd
// instance (memory.max = hard resident-RAM ceiling; trying to go past it
// fails allocations or gets the process OOM-killed, exactly like on real
// constrained hardware). Verified primitives on this machine (cgroup v2,
// delegated user slice): systemd-run --user --scope works unprivileged,
// memory.max OOM-kills at the limit, and cgroup.kill / cgroup.procs of the
// delegated scope are writable/readable by the user.
//
// systemd-run --scope EXECS the target directly (measured: the child keeps
// systemd-run's pid, ppid and process group), so launching through the
// wrapper changes nothing about pgid containment, the /proc ppid walk or the
// shim env — the tree just lives inside a cgroup now.

// systemctl/systemd-run need the user manager; shells may lack these vars
static void ensureSystemdUserEnv(QProcessEnvironment& env)
{
    if (env.value("XDG_RUNTIME_DIR").isEmpty())
        env.insert("XDG_RUNTIME_DIR", QString("/run/user/%1").arg(getuid()));
    if (env.value("DBUS_SESSION_BUS_ADDRESS").isEmpty())
        env.insert("DBUS_SESSION_BUS_ADDRESS",
                   QString("unix:path=/run/user/%1/bus").arg(getuid()));
}

// One-time probe (cached): can this user create a memory-limited scope?
static bool cgroupRamJailAvailable(QString* why)
{
    static int cached = -1;
    static QString cachedWhy;
    if (cached < 0) {
        QProcess p;
        QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
        ensureSystemdUserEnv(env);
        p.setProcessEnvironment(env);
        const QString unit = QString("dsft-probe-%1").arg(QCoreApplication::applicationPid());
        p.setProgram("systemd-run");
        p.setArguments(QStringList{"--user", "--quiet", "--scope", "--unit=" + unit,
                                   "-p", "MemoryMax=16M", "-p", "MemorySwapMax=0",
                                   "/bin/true"});
        p.start();
        if (p.waitForStarted(4000) && p.waitForFinished(8000) &&
            p.exitStatus() == QProcess::NormalExit && p.exitCode() == 0) {
            cached = 1;
            // sweep stale records from previous sessions (crashed GUI, OOM
            // kills) so our dsft-* units never pile up in list-units
            QProcess sweep;
            sweep.setProgram("systemctl");
            sweep.setArguments({"--user", "reset-failed", "dsft-*"});
            sweep.setProcessEnvironment(env);
            sweep.startDetached();
        } else {
            p.kill();
            p.waitForFinished(1000);
            cached = 0;
            cachedWhy = QString::fromLocal8Bit(p.readAllStandardError()).simplified();
            if (cachedWhy.size() > 200) cachedWhy = cachedWhy.left(200) + "…";
            if (cachedWhy.isEmpty())
                cachedWhy = "systemd-run --user failed (no systemd user session?)";
        }
        DBG("[jail] probe: available=%d why=%s", cached, cachedWhy.toUtf8().constData());
    }
    if (why) *why = cachedWhy;
    return cached == 1;
}

QString MainWindow::commOf(pid_t pid) const
{
    const qint64 key = (qint64)pid;
    if (m_registry.contains(key) && !m_registry.value(key).comm.isEmpty())
        return m_registry.value(key).comm;
    return readTextFile(QString("/proc/%1/comm").arg(pid)).replace('/', "_");
}

// One /proc read for everything the meters and the tree walk need: ppid,
// pgrp, utime+stime jiffies and (when rssB is wanted) VmRSS from statm.
// Reading stat ONCE per process per tick instead of 2–3× matters at 4 Hz.
static bool readProcCore(pid_t pid, pid_t* ppid, pid_t* pgrp,
                         qint64* jiffies, qint64* rssB)
{
    static const qint64 pageB = sysconf(_SC_PAGESIZE);
    const QString stat = readTextFile(QString("/proc/%1/stat").arg(pid), 512);
    if (stat.isEmpty()) return false;
    const int rp = stat.lastIndexOf(')');
    if (rp < 0) return false;
    const QStringList f = stat.mid(rp + 2).split(' ', Qt::SkipEmptyParts);
    if (f.size() < 3) return false;
    if (ppid) *ppid = (pid_t)f.at(1).toLong();
    if (pgrp) *pgrp = (pid_t)f.at(2).toLong();
    if (jiffies) *jiffies = f.size() >= 12 ? f.at(10).toLongLong() + f.at(11).toLongLong() : 0;
    if (rssB) {
        *rssB = 0;
        const QString statm = readTextFile(QString("/proc/%1/statm").arg(pid), 128);
        if (!statm.isEmpty()) {
            const QStringList m = statm.split(' ', Qt::SkipEmptyParts);
            if (m.size() >= 2) *rssB = m.at(1).toLongLong() * pageB;   // resident pages
        }
    }
    return true;
}

// All pids that belong to the tree rooted at `root`: /proc ppid-tree + pgrp
// match + shim registry ancestry (catches children that escaped via setsid).
QVector<pid_t> MainWindow::findTreePids(pid_t root) const
{
    QVector<pid_t> out;
    if (root <= 0) return out;
    QSet<pid_t> found;

    // 1) live /proc walk: pid -> (ppid, pgrp)
    struct PInfo { pid_t ppid; pid_t pgrp; };
    QHash<pid_t, PInfo> live;
    QDir proc("/proc");
    const QStringList ids = proc.entryList(QDir::Dirs | QDir::NoDotAndDotDot);
    for (const QString& id : ids) {
        bool ok = false;
        const pid_t pid = id.toLong(&ok);
        if (!ok) continue;
        PInfo v{0, 0};
        if (!readProcCore(pid, &v.ppid, &v.pgrp, nullptr, nullptr)) continue;
        live.insert(pid, v);
    }
    // BFS by ppid from root
    QList<pid_t> frontier{ root };
    while (!frontier.isEmpty()) {
        const pid_t cur = frontier.takeFirst();
        if (found.contains(cur)) continue;
        found.insert(cur);
        for (auto it = live.begin(); it != live.end(); ++it)
            if (it->ppid == cur && !found.contains(it.key()))
                frontier.append(it.key());
    }
    // same process group (catches reparented group members)
    for (auto it = live.begin(); it != live.end(); ++it)
        if (it->pgrp == root) found.insert(it.key());

    // 2) shim registry ancestry (catches exec'd/setsid'd children that
    //    reparented to init — last known parentage still links them)
    QHash<pid_t, pid_t> rparent;
    for (auto it = m_registry.begin(); it != m_registry.end(); ++it)
        rparent.insert((pid_t)it.key(), (pid_t)it.value().ppid);
    for (auto it = rparent.begin(); it != rparent.end(); ++it) {
        pid_t cur = it.key();
        for (int hop = 0; hop < 64 && rparent.contains(cur); ++hop) {
            const pid_t par = rparent.value(cur);
            if (par == root) { found.insert(it.key()); break; }
            cur = par;
        }
    }

    for (pid_t p : std::as_const(found)) out.append(p);
    return out;
}

QVector<pid_t> MainWindow::findTreePids() const { return findTreePids((pid_t)m_rootPid); }

bool MainWindow::hasLiveTree()
{
    for (pid_t p : findTreePids())
        if (procAlive(p)) return true;
    return false;
}

void MainWindow::killTree(int sig)
{
    QSet<pid_t> targets;
    for (pid_t p : findTreePids()) targets.insert(p);
    // every shim-registered process IS a member of this run's tree by
    // definition (only tree members inherit the shim env) — this catches
    // children that escaped via setsid and were reparented
    for (auto it = m_registry.begin(); it != m_registry.end(); ++it)
        targets.insert((pid_t)it.key());
    for (pid_t p : std::as_const(targets)) ::kill(p, sig);
    if (m_rootPid > 0) ::killpg((pid_t)m_rootPid, sig);
    // kernel backstop: at the SIGKILL stage also kill everything still
    // inside the jail scope (cgroup.kill is atomic over the whole subtree —
    // nothing survives by hiding behind another process)
    if (sig == SIGKILL && !m_jailUnit.isEmpty()) killScopeProcs();
}

// The scope's cgroup v2 path, resolved from any member's /proc/<pid>/cgroup
// ("0::/user.slice/.../app.slice/<unit>"). Cached after the first hit.
QString MainWindow::jailCgroupPath()
{
    if (!m_jailCgroup.isEmpty() || m_jailUnit.isEmpty()) return m_jailCgroup;
    QVector<pid_t> pids = findTreePids();
    if (m_rootPid > 0) pids.append((pid_t)m_rootPid);
    const QByteArray unit = m_jailUnit.toLocal8Bit();
    for (pid_t p : pids) {
        QFile f(QString("/proc/%1/cgroup").arg(p));
        if (!f.open(QIODevice::ReadOnly)) continue;
        const QList<QByteArray> lines = f.readAll().split('\n');
        for (const QByteArray& l : lines)
            if (l.startsWith("0::") && l.contains(unit)) {
                m_jailCgroup = QString::fromLocal8Bit(l.mid(3).trimmed());
                DBG("[jail] cgroup: %s", m_jailCgroup.toUtf8().constData());
                return m_jailCgroup;
            }
    }
    // last resort: the default home of user scopes
    const QString guess = QString("/sys/fs/cgroup/user.slice/user-%1.slice/"
                                  "user@%1.service/app.slice/%2").arg(getuid()).arg(m_jailUnit);
    if (QFile::exists(guess)) m_jailCgroup = guess;
    return m_jailCgroup;
}

// SIGKILL every process still inside the scope. Preferred: echo 1 >
// cgroup.kill (atomic, includes descendant cgroups). Fallback: read
// cgroup.procs and kill each pid.
void MainWindow::killScopeProcs()
{
    const QString cg = jailCgroupPath();
    if (cg.isEmpty()) return;
    const QByteArray killFile = (cg + "/cgroup.kill").toLocal8Bit();
    int fd = ::open(killFile.constData(), O_WRONLY);
    if (fd >= 0) {
        const ssize_t r = ::write(fd, "1", 1);
        (void)r;
        ::close(fd);
        DBG("[jail] cgroup.kill written: %s", killFile.constData());
        return;
    }
    const QByteArray procsFile = (cg + "/cgroup.procs").toLocal8Bit();
    QFile f(procsFile);
    if (f.open(QIODevice::ReadOnly)) {
        int killed = 0;
        const QList<QByteArray> lines = f.readAll().split('\n');
        for (const QByteArray& l : lines) {
            bool ok = false;
            const pid_t p = (pid_t)l.toLong(&ok);
            if (ok && p > 1) { ::kill(p, SIGKILL); ++killed; }
        }
        DBG("[jail] cgroup.procs sweep: %d pid(s) killed from %s", killed, procsFile.constData());
    }
}

// Full teardown: kernel kill + ask systemd to drop the unit. Both halves are
// idempotent; called on reset/destructor, so nothing outlives the run. An
// OOM-killed run leaves a "failed" unit RECORD behind — reset-failed clears it.
void MainWindow::stopJailScope()
{
    killScopeProcs();
    if (m_jailUnit.isEmpty()) return;
    QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
    ensureSystemdUserEnv(env);
    for (const QStringList& cmd : {QStringList{"--user", "stop", m_jailUnit},
                                   QStringList{"--user", "reset-failed", m_jailUnit}}) {
        QProcess p;
        p.setProgram("systemctl");
        p.setArguments(cmd);
        p.setProcessEnvironment(env);
        p.startDetached();
    }
    DBG("[jail] systemctl --user stop+reset-failed %s", m_jailUnit.toUtf8().constData());
}

bool MainWindow::isRunning() const { return m_proc.state() != QProcess::NotRunning; }

QString MainWindow::plainOut() const { return m_out->toPlainText(); }


// ------------------------------------------------------------------ state
void MainWindow::resetRunState()
{
    // a kernel-jailed previous run must not outlive its reset
    if (!m_jailUnit.isEmpty()) {
        stopJailScope();
        m_jailUnit.clear();
        m_jailCgroup.clear();
        m_jailKernel = false;
    }
    if (m_evNotifier) { m_evNotifier->setEnabled(false); m_evNotifier->deleteLater(); m_evNotifier = nullptr; }
    if (m_evFd >= 0) { ::close(m_evFd); m_evFd = -1; }
    if (!m_sockPath.isEmpty()) { ::unlink(m_sockPath.toLocal8Bit().constData()); m_sockPath.clear(); }
    if (!m_shmName.isEmpty()) {
        DBG("[run] resetRunState: unlink %s", m_shmName.toLocal8Bit().constData());
        ::shm_unlink(m_shmName.toLocal8Bit().constData());   /* previous run's table */
    }
    disconnect(&m_proc, nullptr, this, nullptr);
    if (m_proc.state() != QProcess::NotRunning) { m_proc.kill(); m_proc.waitForFinished(300); }
    m_registry.clear();
    m_writtenBytes = 0;
    m_peakWritten = 0;
    m_ramBytes = 0;
    m_peakRam = 0;
    m_cpuPct = 0;
    m_cpuOverStreak = 0;
    m_cpuThrottled = false;
    m_cpuLastMs = 0;
    m_cpuLastJiffies = 0;
    if (m_cpuTimer) m_cpuTimer->stop();
    m_ramAnnounced = false;
    m_activeLimits = Limits();
    m_quotaFired = false;
    m_quotaAnnounced = false;
    m_rootKilledBySandbox = false;
    m_sandboxKillWhy.clear();
    m_quotaCleanupDone = false;    m_orphans = 0;
    m_exitLine.clear();
    m_runningPath.clear();
    m_hardKillStage = 0;
    m_stdoutBuf.clear();
    m_stderrBuf.clear();
}

void MainWindow::setMeter(qint64 written, qint64 limitBytes)
{
    m_writtenBytes = written;
    m_peakWritten = qMax(m_peakWritten, written);
    updateStatus();
    Q_UNUSED(limitBytes);
}

// ------------------------------------------------------------------ run
bool MainWindow::runPath(const QString& path, const QString& args, const QString& actionExec)
{
    QFileInfo fi(path);
    if (!fi.exists()) { appendOut("not found: " + path, "#ff8080"); return false; }
    Runnable r;
    r.path = path;
    r.display = fi.fileName();
    if (!actionExec.isEmpty()) {
        r.kind = Runnable::DesktopAction;
        r.actionExec = actionExec;
    } else if (fi.suffix().compare("desktop", Qt::CaseInsensitive) == 0) {
        r.kind = Runnable::Desktop;
    } else {
        r.kind = Runnable::Exe;
    }
    startRun(r, args);
    return true;
}

void MainWindow::startRun(const Runnable& r, const QString& args)
{
    if (isRunning()) { appendOut("already running — press ■ Stop first", "#ff8080"); return; }
    QFileInfo fi(r.path);
    if (!fi.exists()) { appendOut("not found: " + r.path, "#ff8080"); return; }

    QStringList prog;
    DesktopEntry de;
    if (r.kind == Runnable::Desktop || r.kind == Runnable::DesktopAction) {
        de = parseDesktopFile(r.path);
        if (r.kind == Runnable::DesktopAction) de.execLine = r.actionExec;
        if (!de.valid) { appendOut("invalid desktop entry (no Exec): " + r.path, "#ff8080"); return; }
        prog = de.execTokens(args);
        if (prog.isEmpty()) { appendOut("desktop Exec resolved to nothing", "#ff8080"); return; }
    } else {
        const QString suf = fi.suffix().toLower();
        const bool hasExec = fi.permission(QFile::ExeUser) || fi.permission(QFile::ExeGroup)
                             || fi.permission(QFile::ExeOther);
        if (hasExec) {
            prog << fi.absoluteFilePath();
        } else if (suf == "sh" || suf == "bash" || suf == "zsh") {
            prog << "bash" << fi.absoluteFilePath();
        } else if (suf == "py") {
            prog << "python3" << fi.absoluteFilePath();
        } else if (suf == "pl") {
            prog << "perl" << fi.absoluteFilePath();
        } else if (suf == "rb") {
            prog << "ruby" << fi.absoluteFilePath();
        } else {
            appendOut("not runnable (no exec bit): " + r.path, "#ff8080");
            return;
        }
        prog << splitArgs(args);
    }

    resetRunState();
    m_runDisplay = (r.kind == Runnable::Desktop || r.kind == Runnable::DesktopAction)
                       ? (de.name.isEmpty() ? r.display : de.name)
                       : fi.fileName();

    // shim datagram socket + shared memory + env
    const QString uniq = QString("%1-%2").arg(QCoreApplication::applicationPid()).arg(++m_runCounter);
    DBG("[run] startRun #-%s: %s", uniq.toLocal8Bit().constData(),
        prog.join(' ').toLocal8Bit().constData());
    m_sockPath = QString("/tmp/dsft-%1.sock").arg(uniq);
    m_shmName = QString("/dsft-%1").arg(uniq);
    ::unlink(m_sockPath.toLocal8Bit().constData());
    m_evFd = ::socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (m_evFd < 0) {
        appendOut("cannot create shim event socket", "#ff8080");
        return;
    }
    struct sockaddr_un a;
    memset(&a, 0, sizeof a);
    a.sun_family = AF_UNIX;
    strncpy(a.sun_path, m_sockPath.toLocal8Bit().constData(), sizeof(a.sun_path) - 1);
    if (::bind(m_evFd, (struct sockaddr*)&a, sizeof(a)) != 0) {
        appendOut("cannot bind shim event socket: " + QString(strerror(errno)), "#ff8080");
        ::close(m_evFd); m_evFd = -1;
        return;
    }
    m_evNotifier = new QSocketNotifier(m_evFd, QSocketNotifier::Read, this);
    connect(m_evNotifier, &QSocketNotifier::activated, this,
            [this](QSocketDescriptor, QSocketNotifier::Type) { drainEvents(); });

    const Limits lim = m_limits.value(canonical(r.path));
    m_activeLimits = lim;
    const qint64 limitMB = lim.diskMB;
    m_limitMB = limitMB;

    QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
    if (env.value("LC_ALL").isEmpty() && env.value("LANG").isEmpty())
        env.insert("LC_ALL", "C.UTF-8");   // silence Qt's non-UTF8 locale warning
    ensureSystemdUserEnv(env);             // systemd-run needs the user manager
    const QString shim = QCoreApplication::applicationDirPath() + "/libdsftshim.so";
    env.insert("LD_PRELOAD", QFile::exists(shim) ? shim : QString());
    env.insert("DSFT_SHIM_SOCK", m_sockPath);
    env.insert("DSFT_SHM_NAME", m_shmName);
    env.insert("DSFT_QUOTA_MB", QString::number(limitMB));
    env.insert("DSFT_RAM_MB", QString::number(lim.ramMB));
    env.insert("DSFT_RAM_MODE", QString::number(
                   lim.ramMB > 0 ? (lim.ramTerminate ? 1 : (lim.ramOwn ? 2 : 0)) : 0));
    env.insert("DSFT_DISK_BLOCK", QString::number(
                   (lim.diskTerminate || lim.diskDelete) ? 1 : 0));
    m_proc.setProcessEnvironment(env);

    // ---- own-ram jail: kernel-enforced (cgroup scope) with RLIMIT_AS
    // fallback. The LD_PRELOAD malloc jail (DSFT_RAM_MODE=2) stays active as
    // the first layer — malloc-based apps fail their allocations gracefully;
    // the kernel catches everything the shim can't see (raw mmap, glibc
    // internals, static binaries).
    const bool wantRamJail = lim.ramMB > 0 && !lim.ramTerminate && lim.ramOwn;
    bool kernelJail = false;
    QString jailWhy;
    if (wantRamJail)
        kernelJail = cgroupRamJailAvailable(&jailWhy);
    const qint64 ramLimitBytes = (qint64)lim.ramMB * 1024 * 1024;

    QStringList launch = prog;
    if (kernelJail) {
        m_jailKernel = true;
        m_jailUnit = QString("dsft-ram-%1-%2.scope")
                         .arg(QCoreApplication::applicationPid()).arg(m_runCounter);
        m_jailCgroup.clear();
        QStringList wrap{"systemd-run", "--user", "--quiet", "--scope",
                         "--unit=" + m_jailUnit.section('.', 0, 0),
                         "-p", QString("MemoryMax=%1M").arg(lim.ramMB),
                         "-p", "MemorySwapMax=0"};
        wrap += launch;
        launch = wrap;
    }
    const bool rlimitFallback = wantRamJail && !kernelJail;
    m_proc.setProgram(launch.first());
    m_proc.setArguments(launch.mid(1));
    m_proc.setWorkingDirectory(fi.absolutePath());
    m_proc.setChildProcessModifier([rlimitFallback, ramLimitBytes]() {
        ::setpgid(0, 0);
        if (rlimitFallback && ramLimitBytes > 0) {
            struct rlimit rl;
            rl.rlim_cur = (rlim_t)ramLimitBytes;
            rl.rlim_max = (rlim_t)ramLimitBytes;
            ::setrlimit(RLIMIT_AS, &rl);   // counts VIRTUAL memory — warned about below
        }
    });

    connect(&m_proc, &QProcess::readyReadStandardOutput, this, &MainWindow::onProcReadyOut);
    connect(&m_proc, &QProcess::readyReadStandardError, this, &MainWindow::onProcReadyErr);
    connect(&m_proc, &QProcess::finished, this, &MainWindow::onProcFinished);
    connect(&m_proc, &QProcess::errorOccurred, this, &MainWindow::onProcError);
    if (!m_cpuTimer) {
        m_cpuTimer = new QTimer(this);
        connect(m_cpuTimer, &QTimer::timeout, this, &MainWindow::cpuTick);
    }
    m_cpuLastMs = 0;
    m_cpuTimer->start(250);                  // RAM + CPU meters always live while running

    appendActivity(QString("<%1>: start %2  (cwd %3, quota %4)")
                       .arg(m_runDisplay, prog.join(' '), fi.absolutePath(),
                            limitMB > 0 ? QString("%1 MB").arg(limitMB) : "unlimited"));
    if (kernelJail)
        appendActivity(QString("<dsft>: own-ram KERNEL JAIL: cgroup scope %1, "
                               "MemoryMax=%2 MB — the kernel physically caps resident RAM "
                               "(raw mmap included; over the limit = OOM-kill, like a real PC)")
                           .arg(m_jailUnit).arg(lim.ramMB));
    else if (rlimitFallback)
        appendActivity(QString("<dsft>: kernel ram jail UNAVAILABLE (%1) — FALLBACK: "
                               "RLIMIT_AS=%2 MB, which counts VIRTUAL memory: stricter than "
                               "the RSS meter, GUI apps may fail to start")
                           .arg(jailWhy.isEmpty() ? "no systemd user session" : jailWhy)
                           .arg(lim.ramMB));
    m_proc.start();
    m_rootPid = m_proc.processId();     // root of the tree = pgid (setpgid in modifier)
    m_runningPath = canonical(r.path);  // the explorer entry glows while it runs
    refreshRunningMark();
    m_runBtn->setEnabled(false);
    m_stopBtn->setEnabled(true);
    updateStatus();
}

void MainWindow::onRunClicked()
{
    // every selected runnable (multi-select: ctrl = add, alt+click = range)
    QList<Runnable> picked;
    for (QTreeWidgetItem* it : m_tree->selectedItems()) {
        const Runnable r = runnableForItem(it);
        if (r.kind != Runnable::None && it->data(0, Qt::UserRole + 1).toBool())
            picked.append(r);
    }
    if (picked.isEmpty()) { appendOut("select a runnable entry first", "#8a93a2"); return; }
    if (isRunning()) { appendOut("already running — press ■ Stop first", "#ff8080"); return; }

    const Runnable first = picked.takeFirst();
    m_runQueue.clear();
    for (const Runnable& r : picked) m_runQueue.append({ r, m_argEdit->text() });
    if (!m_runQueue.isEmpty())
        appendOut(QString("queue: %1 more selected program(s) will run after this one")
                      .arg(m_runQueue.size()), "#7fd4ff");
    runPath(first.path, m_argEdit->text(),
            first.kind == Runnable::DesktopAction ? first.actionExec : QString());
}

void MainWindow::onStopClicked()
{
    if (m_runQueue.isEmpty() && !isRunning()) { appendOut("nothing is running", "#8a93a2"); return; }
    if (!m_runQueue.isEmpty()) {
        appendOut(QString("queue cleared (%d pending run(s) cancelled)")
                      .arg(m_runQueue.size()), "#8a93a2");
        m_runQueue.clear();
    }
    if (!isRunning()) return;
    appendActivity(QString("<dsft>: stop requested — killing process tree (root pid %1)").arg(m_rootPid));
    m_hardKillStage = 1;
    killTree(SIGTERM);
    if (!m_hardKillTimer) {
        m_hardKillTimer = new QTimer(this);
        m_hardKillTimer->setSingleShot(true);
        connect(m_hardKillTimer, &QTimer::timeout, this, &MainWindow::onHardKillTick);
    }
    m_hardKillTimer->start(500);
}

void MainWindow::stopRun() { onStopClicked(); }

void MainWindow::onHardKillTick()
{
    if (m_hardKillStage == 1) {
        const bool procUp = m_proc.state() != QProcess::NotRunning;
        if (procUp || hasLiveTree()) {
            appendActivity("<dsft>: still alive — escalating to SIGKILL");
            killTree(SIGKILL);
            m_hardKillStage = 2;
            m_hardKillTimer->start(800);
            return;
        }
        m_hardKillStage = 0;
    } else if (m_hardKillStage == 2) {
        if (m_proc.state() != QProcess::NotRunning) {
            appendActivity("<dsft>: force kill");
            m_proc.kill();
        }
        m_hardKillStage = 0;
    }
}

// ------------------------------------------------------------------ stdio
void MainWindow::appendProcLine(const QString& text, const QString& color, bool bold)
{
    appendOut(text, color, bold);
}

void MainWindow::onProcReadyOut()
{
    m_stdoutBuf += m_proc.readAllStandardOutput();
    int idx;
    while ((idx = m_stdoutBuf.indexOf('\n')) >= 0) {
        const QByteArray line = m_stdoutBuf.left(idx);
        m_stdoutBuf.remove(0, idx + 1);
        appendProcLine(QString::fromLocal8Bit(line), "#e8e8e8", false);   // white = program output
    }
}

void MainWindow::onProcReadyErr()
{
    m_stderrBuf += m_proc.readAllStandardError();
    int idx;
    while ((idx = m_stderrBuf.indexOf('\n')) >= 0) {
        const QByteArray line = m_stderrBuf.left(idx);
        m_stderrBuf.remove(0, idx + 1);
        appendProcLine(QString::fromLocal8Bit(line), "#ff9d8c", false);   // soft orange = stderr
    }
}

void MainWindow::onProcError(QProcess::ProcessError err)
{
    if (err == QProcess::FailedToStart) {
        appendOut("failed to start: " + m_proc.program(), "#ff8080");
        m_exitLine = "failed to start";
        m_runBtn->setEnabled(true);
        m_stopBtn->setEnabled(false);
        updateStatus();
    }
}

// ------------------------------------------------------------------ shim events
void MainWindow::drainEvents()
{
    if (m_evFd < 0) return;
    char buf[8192];
    for (;;) {
        const ssize_t n = ::recv(m_evFd, buf, sizeof buf, MSG_DONTWAIT);
        if (n <= 0) break;                       // EAGAIN / EINTR -> done for now
        QString line = QString::fromLocal8Bit(buf, (int)n);
        while (line.endsWith('\n') || line.endsWith('\r')) line.chop(1);
        if (!line.isEmpty()) onShimLine(line);
    }
}

void MainWindow::onShimLine(const QString& line)
{
    DBG("[shim-line] %s", line.toUtf8().constData());
    handleEvent(line.split('|'));
}

void MainWindow::handleEvent(const QStringList& f)
{
    if (f.isEmpty()) return;
    const QString type = f.at(0);
    const qint64 pid = f.size() > 1 ? f.at(1).toLongLong() : 0;

    if (type == "F" && f.size() >= 4) {
        m_registry.insert(pid, { f.at(2).toLongLong(), f.at(3) });
        // late registration after the root exited (e.g. fork+exec'd child of
        // an already-dead parent) — orphan candidate, sweep shortly
        if (m_rootPid > 0 && !isRunning() && !m_lateSweep) {
            m_lateSweep = true;
            QTimer::singleShot(250, this, [this]() {
                m_lateSweep = false;
                if (!isRunning()) sweepOrphans(true);
                updateStatus();
            });
        }
        return;
    }
    if (type == "E" && f.size() >= 4) {
        const QString argv0 = f.at(2);
        const QString cmd = f.mid(3).join('|');
        appendActivity(QString("<%1>: run %2 (pid %3)").arg(argv0, cmd).arg(pid));
        return;
    }
    if ((type == "C" || type == "D") && f.size() >= 3) {
        const QString path = f.mid(2).join('|');
        const QString tag = commOf((pid_t)pid);
        appendActivity(QString("<%1>: %2 %3").arg(tag, type == "C" ? "create" : "rm", path));
        return;
    }
    if (type == "W" && f.size() >= 3) {
        setMeter(f.at(2).toLongLong(), m_limitMB * 1024 * 1024);
        return;
    }
    if (type == "I") {
        appendActivity(QString("<%1>: waiting for input on stdin").arg(commOf((pid_t)pid)));
        m_inEdit->setProperty("needsInput", true);
        m_inEdit->style()->unpolish(m_inEdit);
        m_inEdit->style()->polish(m_inEdit);
        m_inEdit->setFocus();
        return;
    }
    if (type == "R") {                             // allocator-level heap (jail bookkeeping only)
        return;                                    // the METER uses real RSS (cpuTick) instead
    }
    if (type == "RQ") {                            // allocator heap crossed the limit
        // Terminate mode is handled by the RSS meter (cpuTick) — System
        // Monitor semantics. Nothing to do here.
        return;
    }
    if (type == "RM" && f.size() >= 3) {           // own-ram jail hit (rate-limited)
        appendActivity(QString("<%1>: hit its RAM jail (%2 MB) — allocations now fail")
                           .arg(commOf((pid_t)pid)).arg(m_activeLimits.ramMB));
        return;
    }
    if (type == "Q") {                             // disk limit reached
        if (!m_quotaAnnounced) {
            m_quotaAnnounced = true;
            m_quotaFired = true;
            appendActivity(QString("<%1>: DISK QUOTA EXCEEDED (limit %2 MB)")
                               .arg(commOf((pid_t)pid)).arg(m_limitMB));
        }
        if (m_activeLimits.diskTerminate)
            enforceQuota((pid_t)pid, QString("disk quota exceeded (limit %1 MB)").arg(m_limitMB));
        else if (m_activeLimits.diskDelete) {
            // no kill: delete everything the tree created instantly; the shim
            // resets its over-flag so the app continues, limited but alive
            appendActivity("<dsft>: deleting what the program created (limit reached, terminate off)");
            cleanupQuotaFiles();
            m_quotaCleanupDone = true;
        }
        return;
    }
}

// ------------------------------------------------------------------ sandbox enforcement
// CONTAINMENT: when the limit is reached, the ENTIRE launched tree dies —
// the program you ran and everything it spawned, however deep. Its created
// files are then deleted, which also frees the counted usage.
void MainWindow::enforceQuota(pid_t offender, const QString& why)
{
    Q_UNUSED(offender);
    if (m_rootKilledBySandbox) return;              // already handling it
    m_rootKilledBySandbox = true;
    m_quotaFired = true;
    m_sandboxKillWhy = why;

    appendActivity(QString("<dsft>: sandbox: terminating the program tree — %1").arg(why));
    m_hardKillStage = 1;
    killTree(SIGTERM);
    if (!m_hardKillTimer) {
        m_hardKillTimer = new QTimer(this);
        m_hardKillTimer->setSingleShot(true);
        connect(m_hardKillTimer, &QTimer::timeout, this, &MainWindow::onHardKillTick);
    }
    m_hardKillTimer->start(250);
}

void MainWindow::cleanupQuotaFiles(const QSet<qint64>& creators, const QString& shmName)
{
    m_quotaCleanupDone = true;
    // use the SHM of the run that enforced — a late tick must never touch a
    // newer run's table (pids get reused!)
    const QString name = !shmName.isEmpty() ? shmName : m_shmName;
    if (name.isEmpty()) return;
    const QByteArray nm = name.toLocal8Bit();
    int fd = ::shm_open(nm.constData(), O_RDWR, 0600);
    if (fd < 0) {
        DBG("[quota] cleanup: shm_open(%s) failed: %s", nm.constData(), strerror(errno));
        appendActivity("<dsft>: sandbox cleanup: no file table (shim did not run)");
        return;
    }
    void* mem = ::mmap(nullptr, sizeof(SharedState), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    ::close(fd);
    if (mem == MAP_FAILED) {
        DBG("[quota] cleanup: mmap failed: %s", strerror(errno));
        return;
    }
    SharedState* S = (SharedState*)mem;
    DBG("[quota] cleanup start: shm=%s nfiles=%u written=%llu", nm.constData(),
        (unsigned)S->nfiles, (unsigned long long)S->written);
    int deleted = 0;
    if (qEnvironmentVariableIsSet("DSFT_DEBUG")) {
        pthread_mutex_lock(&S->lock);
        for (uint32_t d = 0; d < S->nfiles && d < DSFT_MAX_FILES; ++d)
            DBG("[quota] table[%u] = %s creator=%d contrib=%llu",
                d, S->files[d], (int)S->filepid[d],
                (unsigned long long)S->filecontrib[d]);
        pthread_mutex_unlock(&S->lock);
    }
    uint32_t i = 0;
    pthread_mutex_lock(&S->lock);
    while (i < S->nfiles && i < DSFT_MAX_FILES) {
        const bool match = S->files[i][0] != 0 &&
                           (creators.isEmpty() || creators.contains((qint64)S->filepid[i]));
        if (!match) { ++i; continue; }
        const QString p = QString::fromLocal8Bit(S->files[i]);
        pthread_mutex_unlock(&S->lock);           // file IO outside the lock

        QFileInfo fi(p);
        if (fi.exists()) {
            const bool ok = fi.isDir() ? QDir(p).removeRecursively() : QFile::remove(p);
            if (ok) {
                ++deleted;
                appendActivity(QString("<dsft>: sandbox deleted %1").arg(p));
            }
            DBG("[quota] cleanup %s exists=%d removed=%d creator=%d",
                p.toUtf8().constData(), (int)fi.exists(), (int)ok,
                (int)S->filepid[i]);
        }
        pthread_mutex_lock(&S->lock);
        // freed space: subtract the file's counted bytes from net usage
        if (S->filecontrib[i] <= S->written) S->written -= S->filecontrib[i];
        else S->written = 0;
        const uint32_t last = S->nfiles - 1;
        if (i != last) {
            memcpy(S->files[i], S->files[last], DSFT_PATHBUF);
            S->filepid[i] = S->filepid[last];
            S->filecontrib[i] = S->filecontrib[last];
        }
        S->files[last][0] = 0;
        S->filepid[last] = 0;
        S->filecontrib[last] = 0;
        S->nfiles--;
        // do not ++i: the swapped-in entry must be re-checked
    }
    pthread_mutex_unlock(&S->lock);
    ::munmap(mem, sizeof(SharedState));
    if (!deleted) appendActivity("<dsft>: sandbox cleanup: nothing left to delete");
    // sync the live meter with the freed space
    m_writtenBytes = 0;
    updateStatus();
}

// ------------------------------------------------------------- live meters (RAM + CPU)
// Runs 4×/second while ANY program is active. Values are task-manager grade:
//  - RAM  = resident set (VmRSS) summed over the WHOLE tree — the number
//           System Monitor / task manager shows, not allocator accounting
//  - CPU  = % of ALL cores (100% = the machine's full capacity)
// Enforcement:
//  - RAM terminate mode: RSS of the tree over the limit → whole tree dies
//  - own-ram jail:       the shim still fails allocations beyond the limit
//  - CPU terminate:      sustained (2 ticks) over the limit → tree dies
//  - own-cpu jail:       SIGSTOP/SIGCONT duty-cycling keeps it near N%
void MainWindow::cpuTick()
{
    if (!isRunning()) return;

    static const qint64 hz = sysconf(_SC_CLK_TCK);
    static const qint64 ncores = qMax<qint64>(1, sysconf(_SC_NPROCESSORS_ONLN));
    const qint64 root = m_rootPid;

    // ONE /proc pass per tick: tree membership + jiffies + RSS together
    // (previously findTreePids() re-read every stat and then this loop read
    // them all AGAIN — 2–3 reads per process per tick at 4 Hz)
    struct PLive { pid_t ppid; pid_t pgrp; qint64 jiffies; qint64 rss; };
    QHash<pid_t, PLive> live;
    const QDir procDir("/proc");
    const QStringList ids = procDir.entryList(QDir::Dirs | QDir::NoDotAndDotDot);
    for (const QString& id : ids) {
        bool ok = false;
        const pid_t pid = id.toLong(&ok);
        if (!ok) continue;
        PLive v{0, 0, 0, 0};
        if (!readProcCore(pid, &v.ppid, &v.pgrp, &v.jiffies, &v.rss)) continue;
        live.insert(pid, v);
    }
    // tree membership: BFS by ppid from the root + pgrp + registry ancestry
    // (same containment semantics as findTreePids, on the data we already read)
    QSet<pid_t> found;
    if (root > 0) {
        QList<pid_t> frontier{ (pid_t)root };
        while (!frontier.isEmpty()) {
            const pid_t cur = frontier.takeFirst();
            if (found.contains(cur)) continue;
            found.insert(cur);
            for (auto it = live.begin(); it != live.end(); ++it)
                if (it->ppid == cur && !found.contains(it.key()))
                    frontier.append(it.key());
        }
        for (auto it = live.begin(); it != live.end(); ++it)
            if (it->pgrp == (pid_t)root) found.insert(it.key());
        QHash<pid_t, pid_t> rparent;
        for (auto it = m_registry.begin(); it != m_registry.end(); ++it)
            rparent.insert((pid_t)it.key(), (pid_t)it.value().ppid);
        for (auto it = rparent.begin(); it != rparent.end(); ++it) {
            pid_t cur = it.key();
            for (int hop = 0; hop < 64 && rparent.contains(cur); ++hop) {
                const pid_t par = rparent.value(cur);
                if (par == (pid_t)root) { found.insert(it.key()); break; }
                cur = par;
            }
        }
    }
    QVector<pid_t> pids;
    pids.reserve(found.size());
    qint64 total = 0;
    qint64 rss = 0;
    for (pid_t p : std::as_const(found)) {
        pids.append(p);
        const auto lit = live.constFind(p);
        if (lit != live.constEnd()) {
            total += lit->jiffies;             // utime + stime
            rss += lit->rss;                   // resident bytes
        }
    }

    // ---- RAM meter: real resident memory of the tree (System Monitor style)
    m_ramBytes = rss;
    m_peakRam = qMax(m_peakRam, m_ramBytes);

    // ---- CPU delta (% of ALL cores)
    const qint64 nowMs = QDateTime::currentMSecsSinceEpoch();
    qint64 dJiff = -1, dMs = 0;
    if (m_cpuLastMs != 0) {
        dJiff = qMax<qint64>(0, total - m_cpuLastJiffies);
        dMs = qMax<qint64>(1, nowMs - m_cpuLastMs);
        m_cpuPct = (int)qBound<qint64>(qint64(0), dJiff * 100000 / (dMs * hz * ncores), qint64(100));
    }
    m_cpuLastJiffies = total;
    m_cpuLastMs = nowMs;
    updateStatus();

    // ---- RAM terminate: RSS over the limit → containment kill
    if (m_activeLimits.ramMB > 0 && m_activeLimits.ramTerminate &&
        m_ramBytes > (qint64)m_activeLimits.ramMB * 1024 * 1024) {
        if (!m_ramAnnounced) {
            m_ramAnnounced = true;
            appendActivity(QString("<dsft>: RAM LIMIT EXCEEDED (%1 MB resident > %2 MB)")
                               .arg(m_ramBytes / (1024 * 1024)).arg(m_activeLimits.ramMB));
        }
        enforceQuota(0, QString("RAM limit exceeded (%1 MB resident > %2 MB)")
                            .arg(m_ramBytes / (1024 * 1024))
                            .arg(m_activeLimits.ramMB));
        return;
    }

    const int limit = m_activeLimits.cpuPct;
    if (limit <= 0 || dJiff < 0) return;     // no CPU limit (or first tick): meter only

    if (m_activeLimits.cpuOwn) {
        // own-cpu jail: throttle the tree to limit% of ALL cores' time
        const qint64 allowedMs = qMax<qint64>(1, dMs * ncores * limit / 100);
        const qint64 usedMs = dJiff * 1000 / hz;
        if (!m_cpuThrottled && usedMs > allowedMs && limit < 100) {
            for (pid_t p : pids) if (p > 1) ::kill(p, SIGSTOP);   // pids: fresh from this tick
            m_cpuThrottled = true;
            const int stopMs = (int)qBound<qint64>(60, dMs - allowedMs / ncores, dMs);
            QTimer::singleShot(stopMs, this, [this]() {
                if (isRunning())
                    for (pid_t p : findTreePids()) if (p > 1) ::kill(p, SIGCONT);
                m_cpuThrottled = false;
            });
        }
        return;
    }

    // terminate mode: sustained (2 consecutive ticks) over the limit
    if (m_cpuPct > limit) {
        if (++m_cpuOverStreak >= 2) {
            m_cpuOverStreak = 0;
            if (!m_quotaAnnounced) {
                m_quotaAnnounced = true;
                appendActivity(QString("<dsft>: CPU LIMIT EXCEEDED (sustained %1% > %2%)")
                                   .arg(m_cpuPct).arg(limit));
            }
            enforceQuota(0, QString("CPU limit exceeded (%1% sustained > %2%)")
                                .arg(m_cpuPct).arg(limit));
        }
    } else {
        m_cpuOverStreak = 0;
    }
}

// ------------------------------------------------------------------ finish + orphans
void MainWindow::sweepOrphans(bool report)
{
    DBG("[sweep] root=%lld registry=%d", (long long)m_rootPid, m_registry.size());
    QSet<pid_t> reported;
    // 1) shim-registered members still alive after the root exited
    for (auto it = m_registry.begin(); it != m_registry.end(); ++it) {
        const pid_t p = (pid_t)it.key();
        if ((qint64)p == m_rootPid) continue;
        reported.insert(p);
        if (!procAlive(p)) continue;
        ++m_orphans;
        const QString comm = it.value().comm;
        if (report)
            appendActivity(QString("<dsft>: orphan detected: %1 (pid %2) still running after exit")
                               .arg(comm).arg(p));
        if (m_autoKill->isChecked()) {
            ::kill(p, SIGKILL);
            if (report)
                appendActivity(QString("<dsft>: orphan killed: %1 (pid %2)").arg(comm).arg(p));
        }
    }
    // 2) non-shimmed tree members (fork-only children without exec) via /proc
    for (pid_t p : findTreePids()) {
        if ((qint64)p == m_rootPid || reported.contains(p)) continue;
        if (!procAlive(p)) continue;
        ++m_orphans;
        const QString comm = commOf(p);
        if (report)
            appendActivity(QString("<dsft>: orphan detected: %1 (pid %2) still running after exit")
                               .arg(comm).arg(p));
        if (m_autoKill->isChecked()) {
            ::kill(p, SIGKILL);
            if (report)
                appendActivity(QString("<dsft>: orphan killed: %1 (pid %2)").arg(comm).arg(p));
        }
    }
}

void MainWindow::onProcFinished(int exitCode, QProcess::ExitStatus st)
{
    if (m_hardKillTimer) m_hardKillTimer->stop();
    if (m_cpuTimer) m_cpuTimer->stop();
    m_hardKillStage = 0;

    QString line = (st == QProcess::NormalExit)
                       ? QString("exit code %1").arg(exitCode)
                       : QString("crashed (killed by signal %1)").arg(exitCode);
    if (m_rootKilledBySandbox)
        line += " — terminated by sandbox (" +
                (m_sandboxKillWhy.isEmpty() ? QStringLiteral("limit reached") : m_sandboxKillWhy) + ")";
    if (m_jailKernel && st == QProcess::CrashExit && exitCode == SIGKILL)
        line += QString(" — kernel RAM jail: OOM-killed at %1 MB (memory.max reached)")
                    .arg(m_activeLimits.ramMB);
    appendOut(line, "#8a93a2");
    m_exitLine = line;
    m_runningPath.clear();              // un-glow the explorer entry
    refreshRunningMark();

    // discord-style case: app reported exit but left children on screen.
    // Sweep deferred so children that exec'd just before the parent died
    // (their shim F arrives late) get registered first.
    const qint64 doneRoot = m_rootPid;
    QTimer::singleShot(350, this, [this, doneRoot]() {
        if (!isRunning() && m_rootPid == doneRoot) {
            sweepOrphans(true);
            updateStatus();
        }
    });

    // whole tree dead because the ROOT overflowed -> delete everything the
    // tree created; otherwise per-subtree cleanup already ran at enforcement
    if (m_quotaFired && m_rootKilledBySandbox && !m_quotaCleanupDone)
        cleanupQuotaFiles();

    // batch queue: launch the next selected program
    if (!m_runQueue.isEmpty()) {
        const QPair<Runnable, QString> next = m_runQueue.takeFirst();
        appendOut(QString("queue: starting %1 (%d left)")
                      .arg(next.first.display).arg(m_runQueue.size()), "#8a93a2");
        QTimer::singleShot(200, this, [this, next]() {
            if (!isRunning()) startRun(next.first, next.second);
        });
    }

    // one final drain for datagrams already queued at exit. The socket stays
    // bound + notifier armed so LATE shim registrations (children that exec'd
    // just as the parent died) still arrive and can be swept as orphans.
    // Teardown happens at the next startRun / app exit.
    if (m_evFd >= 0) drainEvents();

    m_runBtn->setEnabled(true);
    m_stopBtn->setEnabled(false);
    m_inEdit->setProperty("needsInput", false);
    m_inEdit->style()->unpolish(m_inEdit);
    m_inEdit->style()->polish(m_inEdit);
    updateStatus();
}
