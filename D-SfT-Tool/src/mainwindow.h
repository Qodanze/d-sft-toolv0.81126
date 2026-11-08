#pragma once
#include <QMainWindow>
#include <QProcess>
#include <QSocketNotifier>
#include <QTreeWidget>
#include <QLineEdit>
#include <QCheckBox>
#include <QPushButton>
#include <QLabel>
#include <QPlainTextEdit>
#include <QPointer>
#include <QFileInfo>
#include <QTimer>
#include <QVector>
#include <QSet>
#include <QHash>
#include <QStringList>
#include <QElapsedTimer>
#include <cstdio>
#include <sys/types.h>
#include "desktopentry.h"

// DSFT_DEBUG=1 taps (unbuffered stderr, single shared clock)
inline qint64 dsftDbgMs()
{
    static QElapsedTimer t;
    if (!t.isValid()) t.start();
    return t.elapsed();
}
#define DBG(...) do { if (qEnvironmentVariableIsSet("DSFT_DEBUG")) { \
    fprintf(stderr, "[%lld] ", (long long)dsftDbgMs()); fprintf(stderr, __VA_ARGS__); } } while (0)

class MainWindow;

namespace DSfT { int runSelfTest(); }

// One runnable thing in the tree.
struct Runnable {
    enum Kind { Exe, Script, Desktop, DesktopAction, None } kind = None;
    QString path;          // file path (desktop file path for Desktop*)
    QString display;       // shown in output
    QString actionExec;    // for DesktopAction
    QString actionName;
};

inline QString canonical(const QString& p) { return QFileInfo(p).canonicalFilePath(); }

// Per-program limitation set (edited in the Limitations config dialog).
struct Limits {
    qint64 diskMB = 0;              // 0 = unlimited
    bool diskTerminate = true;      // kill the tree when the disk limit is hit
    bool diskDelete = true;         // delete what the tree created when hit
    qint64 ramMB = 0;               // 0 = unlimited
    bool ramTerminate = true;       // kill the tree when the RAM limit is hit
    bool ramOwn = false;            // own-ram jail: allocations FAIL beyond the limit
    int cpuPct = 0;                 // % of one core, 0 = unlimited
    bool cpuTerminate = true;       // kill the tree when sustained CPU > limit
    bool cpuOwn = false;            // own-cpu jail: throttled to N% (slower PC)
    bool any() const { return diskMB > 0 || ramMB > 0 || cpuPct > 0; }
    // short column summary, e.g. "D90T R256J C20J"
    QString summary() const
    {
        QStringList parts;
        if (diskMB > 0) parts << QString("D%1%2").arg(diskMB)
            .arg(diskTerminate ? "T" : (diskDelete ? "D" : ""));
        if (ramMB > 0) parts << QString("R%1%2").arg(ramMB)
            .arg(ramTerminate ? "T" : (ramOwn ? "J" : ""));
        if (cpuPct > 0) parts << QString("C%1%2").arg(cpuPct)
            .arg(cpuTerminate ? "T" : (cpuOwn ? "J" : ""));
        return parts.join(' ');
    }
};

class MainWindow : public QMainWindow
{
    Q_OBJECT
public:
    explicit MainWindow(QWidget* parent = nullptr);
    ~MainWindow() override;

    // ---- used by selftest ----
    bool addPathToTree(const QString& path);          // returns false on error
    bool runPath(const QString& path, const QString& args = QString(),
                 const QString& actionExec = QString());
    void stopRun();
    bool isRunning() const;
    QString plainOut() const;                         // terminal text (no tags)
    const QStringList& activityLog() const { return m_activity; }
    QTreeWidget* tree() const { return m_tree; }
    Limits limitsFor(const QString& path) const { return m_limits.value(path); }
    void setQuotaFor(const QString& path, qint64 mb);
    void setLimitsFor(const QString& path, const Limits& l);
    void clearOutput();
    void saveSettings();
    void sendStdin(const QString& text);
    bool hasQuotaHit() const { return m_quotaFired; }
    QString lastExitLine() const { return m_exitLine; }
    int orphanCount() const { return m_orphans; }
    void prepareForTest();                            // clears state, resets sandbox dir
    qint64 peakWritten() const { return m_peakWritten; }
    qint64 peakRam() const { return m_peakRam; }

private slots:
    void onAddPath();
    void onAddFiles();
    void onRunClicked();
    void onStopClicked();
    void onSandboxForSelection();
    void onItemExpanded(QTreeWidgetItem* it);
    void onItemDoubleClicked(QTreeWidgetItem* it, int col);
    void onTreeClicked(QTreeWidgetItem* it, int col);
    void onTreeContextMenu(const QPoint& pos);
    void onSendInput();

    // runner slots (implemented in runner.cpp)
    void onProcReadyOut();
    void onProcReadyErr();
    void onProcFinished(int exitCode, QProcess::ExitStatus st);
    void onProcError(QProcess::ProcessError err);
    void onShimLine(const QString& line);
    void drainEvents();
    void onHardKillTick();
    void applyFilter();

protected:
    bool eventFilter(QObject* obj, QEvent* ev) override;

private:
    // tree building (mainwindow.cpp)
    void populateDirItem(QTreeWidgetItem* dirItem);
    QTreeWidgetItem* makeFileItem(const QString& path);
    QTreeWidgetItem* makeDirItem(const QString& path);
    QTreeWidgetItem* findChildEntry(QTreeWidgetItem* parent, const QString& text0) const;
    void flatVisible(QList<QTreeWidgetItem*>& out, QTreeWidgetItem* parent) const;
    void onClearAll();
    void onTreeSelectionChanged();
    void cpuTick();
    void updateSandboxColumnText();
    void updateSandboxColumn(QTreeWidgetItem* it);
    static bool isRunnableFile(const QFileInfo& fi, QString* reason);
    void openSandboxDialog(QTreeWidgetItem* it);
    void appendOut(const QString& plain, const QString& color = "#e8e8e8", bool bold = false);
    void appendActivity(const QString& line);         // yellow bold + m_activity
    void refreshRunningMark();                        // green-bold the running tree entry
    void logSelectInfo();
    void loadSettings();
    QString configDir() const;
    Runnable runnableForItem(QTreeWidgetItem* it) const;

    // runner (runner.cpp)
    void startRun(const Runnable& r, const QString& args);
    void killTree(int sig);
    void sweepOrphans(bool report);
    QVector<pid_t> findTreePids() const;
    QVector<pid_t> findTreePids(pid_t root) const;
    void enforceQuota(pid_t offender, const QString& why = QStringLiteral("limit reached"));
    void cleanupQuotaFiles(const QSet<qint64>& creators = QSet<qint64>(),
                           const QString& shmName = QString());
    void resetRunState();
    // own-ram kernel jail (cgroup v2 scope via systemd-run --user --scope)
    QString jailCgroupPath();               // resolve + cache the scope's cgroup v2 path
    void killScopeProcs();                  // SIGKILL every process still inside the scope
    void stopJailScope();                   // kernel kill + systemd unit teardown
    void handleEvent(const QStringList& f);
    QString commOf(pid_t pid) const;
    static bool procAlive(pid_t pid);
    bool hasLiveTree();
    void appendProcLine(const QString& text, const QString& color, bool bold);
    void setMeter(qint64 written, qint64 limitBytes);
    void updateStatus();

    // ---- UI ----
    QTreeWidget* m_tree = nullptr;
    QPlainTextEdit* m_out = nullptr; // fwd include? include below
    QLineEdit* m_argEdit = nullptr;
    QLineEdit* m_inEdit = nullptr;
    QCheckBox* m_autoScroll = nullptr;
    QCheckBox* m_autoKill = nullptr;
    QPushButton* m_runBtn = nullptr;
    QPushButton* m_stopBtn = nullptr;
    QPushButton* m_addBtn = nullptr;
    QPushButton* m_addFileBtn = nullptr;
    QPushButton* m_sandboxBtn = nullptr;
    QLineEdit* m_searchEdit = nullptr;
    QLabel* m_lblState = nullptr;
    QLabel* m_lblDisk = nullptr;
    QLabel* m_lblRam = nullptr;
    QLabel* m_lblCpu = nullptr;

    // ---- run state ----
    QProcess m_proc;
    int m_evFd = -1;                        // AF_UNIX datagram socket for shim events
    QSocketNotifier* m_evNotifier = nullptr;
    QString m_sockPath;
    QString m_shmName;
    qint64 m_rootPid = 0;              // pid of the process we spawned
    qint64 m_writtenBytes = 0;
    qint64 m_limitMB = 0;              // active run limit (0 = unlimited)
    bool m_quotaFired = false;
    bool m_quotaCleanupDone = false;
    int m_orphans = 0;
    int m_hardKillStage = 0;
    QString m_exitLine;
    QStringList m_activity;            // yellow lines (plain text)
    struct ProcRow { qint64 ppid; QString comm; };
    QHash<qint64, ProcRow> m_registry; // shimmed pid -> parent,comm
    QString m_runDisplay;              // app tag for activity lines
    QString m_runningPath;             // canonical path of the entry currently running ("" = none)
    QHash<QString, Limits> m_limits;   // canonical path -> limitation set
    Limits m_activeLimits;             // limits of the run in flight
    QTimer* m_hardKillTimer = nullptr;
    QByteArray m_stdoutBuf;
    QByteArray m_stderrBuf;
    int m_runCounter = 0;
    bool m_lateSweep = false;
    qint64 m_peakWritten = 0;           // max live disk usage seen this run
    qint64 m_peakRam = 0;               // max live heap usage seen this run
    qint64 m_ramBytes = 0;              // live heap bytes of the tree (R events)
    int m_cpuPct = 0;                   // measured tree CPU (% of one core)
    QTimer* m_cpuTimer = nullptr;
    qint64 m_cpuLastJiffies = 0;
    qint64 m_cpuLastMs = 0;
    int m_cpuOverStreak = 0;
    bool m_cpuThrottled = false;
    bool m_quotaAnnounced = false;      // yellow QUOTA line logged once per run
    bool m_ramAnnounced = false;        // yellow RAM line logged once per run
    bool m_rootKilledBySandbox = false;
    QString m_sandboxKillWhy;          // what triggered the containment kill (RAM/CPU/disk)
    QList<QPair<Runnable, QString>> m_runQueue;   // multi-select batch runs
    // own-ram kernel jail state (empty unit = this run is not kernel-jailed)
    QString m_jailUnit;                // systemd scope unit, e.g. "dsft-ram-1234-1.scope"
    QString m_jailCgroup;              // resolved cgroup v2 path of the scope
    bool m_jailKernel = false;         // true = cgroup scope; false+ramOwn = RLIMIT_AS fallback
    friend int DSfT::runSelfTest();
};
