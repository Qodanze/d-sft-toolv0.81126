// D-SfT Tool - main window: UI, tree explorer, sandbox dialog, settings.
// Process management lives in runner.cpp.
#include "mainwindow.h"
#include "desktopentry.h"

#include <QApplication>
#include <QStyle>
#include <QFileDialog>
#include <QFileInfo>
#include <QDir>
#include <QDirIterator>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QSplitter>
#include <QHeaderView>
#include <QStatusBar>
#include <QLabel>
#include <QSpinBox>
#include <QDialog>
#include <QDialogButtonBox>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QFile>
#include <QScrollBar>
#include <QMessageBox>
#include <QMimeDatabase>
#include <QMimeType>
#include <QRadioButton>
#include <QStyledItemDelegate>
#include <QMenu>
#include <QGroupBox>
#include <QShortcut>
#include <QEvent>
#include <QMouseEvent>
#include <QPainter>
#include <unistd.h>

// ------------------------------------------------------------------ delegate
// Paints a gear glyph in column 3 for runnable rows (click = sandbox dialog).
class GearDelegate : public QStyledItemDelegate
{
public:
    explicit GearDelegate(QObject* parent) : QStyledItemDelegate(parent) {}
    void paint(QPainter* p, const QStyleOptionViewItem& opt,
               const QModelIndex& idx) const override
    {
        if (idx.column() == 3) {
            const QTreeWidget* t = qobject_cast<const QTreeWidget*>(idx.model() ? idx.model()->parent() : nullptr);
            Q_UNUSED(t);
            p->save();
            if (opt.state.testFlag(QStyle::State_MouseOver)) {
                p->fillRect(opt.rect, QColor(255, 255, 255, 12));
            }
            const QString txt = idx.data(Qt::DisplayRole).toString();
            const bool runnable = idx.siblingAtColumn(0).data(Qt::UserRole + 1).toBool();
            if (runnable) {
                QIcon gear = QIcon::hasThemeIcon("configure")
                                 ? QIcon::fromTheme("configure")
                                 : QApplication::style()->standardIcon(QStyle::SP_ComputerIcon);
                gear.paint(p, opt.rect.adjusted(2, 1, -2, -1), Qt::AlignLeft | Qt::AlignVCenter);
            }
            if (!txt.isEmpty()) {
                p->setPen(QColor("#9aa4b2"));
                p->drawText(opt.rect.adjusted(24, 0, 0, 0),
                            Qt::AlignLeft | Qt::AlignVCenter, txt);
            }
            p->restore();
            return;
        }
        QStyledItemDelegate::paint(p, opt, idx);
    }
};

// ------------------------------------------------------------------ helpers
// (canonical() + DBG() live in mainwindow.h as inline helpers)

// --- type art: one consistent hue per file category, used by BOTH the Type
// column text and the drawn fallback icons (color theory: green = runnable
// and safe to execute, cyan = desktop/config, violet = image, red = video,
// teal = audio, amber = archive, gray = inert data)
struct TypeArt { QColor col; const char* tag; };
static TypeArt typeArt(const QString& mime, bool runnable, const QString& reason)
{
    if (runnable) {
        if (reason == "desktop entry") return { QColor("#7fd4ff"), "APP" };
        if (reason == "script")        return { QColor("#a3e635"), "SH"  };
        return { QColor("#4ade80"), "EXE" };
    }
    if (mime.startsWith("image/"))    return { QColor("#c084fc"), "IMG" };
    if (mime.startsWith("video/"))    return { QColor("#f87171"), "VID" };
    if (mime.startsWith("audio/"))    return { QColor("#2dd4bf"), "AUD" };
    if (mime.contains("zip") || mime.contains("tar") || mime.contains("compressed") ||
        mime.contains("rar") || mime.contains("7z"))
                                      return { QColor("#fbbf24"), "ARC" };
    if (mime.endsWith("x-desktop"))   return { QColor("#7fd4ff"), "APP" };
    if (mime.contains("shellscript")) return { QColor("#a3e635"), "SH"  };
    if (mime.startsWith("text/"))     return { QColor("#9aa4b2"), "TXT" };
    return { QColor("#7a8494"), "BIN" };
}

// Content-sniffed mime type (magic bytes — a renamed .png is still
// recognized by its content). One shared QMimeDatabase.
static QMimeType iconMime(const QFileInfo& fi)
{
    static QMimeDatabase db;
    return db.mimeTypeForFile(fi.absoluteFilePath());
}

// Type icon for an already-sniffed mime: resolved through the desktop icon
// theme; genres the theme lacks get a drawn fallback glyph. Cached per mime
// icon name so big folders only pay the lookup once.
static QIcon iconForMimeType(const QMimeType& mt)
{
    static QHash<QString, QIcon> cache;
    const QString key = mt.iconName();
    auto it = cache.constFind(key);
    if (it != cache.constEnd()) return *it;
    QIcon ic;
    if (QIcon::hasThemeIcon(key)) {
        ic = QIcon::fromTheme(key);
    } else {
        const TypeArt art = typeArt(mt.name(), false, QString());
        QPixmap pm(64, 64);
        pm.fill(Qt::transparent);
        QPainter p(&pm);
        p.setRenderHint(QPainter::Antialiasing);
        p.setBrush(QColor("#181c23"));
        p.setPen(QPen(art.col, 2));
        p.drawRoundedRect(3, 3, 58, 58, 10, 10);
        QFont f = p.font();
        f.setBold(true);
        f.setPixelSize(17);
        p.setFont(f);
        p.setPen(art.col);
        p.drawText(pm.rect(), Qt::AlignCenter, art.tag);
        p.end();
        ic = QIcon(pm);
    }
    cache.insert(key, ic);
    return ic;
}


// Optimal-string-alignment distance (Damerau-Levenshtein, adjacent swaps),
// capped: returns cap+1 when the distance exceeds `cap`.
static int osaDistance(const QString& a, const QString& b, int cap)
{
    const int n = a.size(), m = b.size();
    if (qAbs(n - m) > cap) return cap + 1;
    static int dp[64][64];
    if (n >= 64 || m >= 64) return cap + 1;
    for (int i = 0; i <= n; ++i) dp[i][0] = i;
    for (int j = 0; j <= m; ++j) dp[0][j] = j;
    for (int i = 1; i <= n; ++i) {
        for (int j = 1; j <= m; ++j) {
            const int cost = (a[i-1] == b[j-1]) ? 0 : 1;
            int v = qMin(dp[i-1][j] + 1, qMin(dp[i][j-1] + 1, dp[i-1][j-1] + cost));
            if (i > 1 && j > 1 && a[i-1] == b[j-2] && a[i-2] == b[j-1])
                v = qMin(v, dp[i-2][j-2] + 1);       // transposition
            dp[i][j] = v;
        }
    }
    return dp[n][m];
}

static bool isSubsequence(const QString& text, const QString& q)
{
    int pos = 0;
    for (const QChar c : q) {
        pos = text.indexOf(c, pos);
        if (pos < 0) return false;
        ++pos;
    }
    return true;
}

// -1 = no match; higher = better. Tolerates typos ("kansole" -> konsole 555).
static int fuzzyScore(const QString& text, const QString& rawQuery)
{
    if (rawQuery.isEmpty()) return 1000;
    const QString t = text.toLower();
    const QString q = rawQuery.toLower();
    if (t == q) return 1000;
    if (t.startsWith(q)) return 950;
    const int idx = t.indexOf(q);
    if (idx >= 0) return 900 - qMin(idx, 60);
    const int dl = osaDistance(t, q, 2);
    if (dl <= 2) return 700 - dl * 150;
    if (isSubsequence(t, q)) return 300;
    return -1;
}

bool MainWindow::isRunnableFile(const QFileInfo& fi, QString* reason)
{
    if (fi.isDir() || !fi.isFile()) { if (reason) *reason = "not a file"; return false; }
    if (fi.isExecutable()) { if (reason) *reason = "executable"; return true; }
    if (fi.suffix().compare("desktop", Qt::CaseInsensitive) == 0) { if (reason) *reason = "desktop entry"; return true; }
    static const QStringList scriptExt = {"sh", "bash", "py", "pl", "rb", "zsh"};
    if (scriptExt.contains(fi.suffix().toLower())) { if (reason) *reason = "script"; return true; }
    // shebang?
    QFile f(fi.absoluteFilePath());
    if (f.open(QIODevice::ReadOnly)) {
        QByteArray head = f.read(2);
        f.close();
        if (head == "#!") { if (reason) *reason = "shebang script"; return true; }
    }
    if (reason) *reason = "not runnable";
    return false;
}

MainWindow::MainWindow(QWidget* parent) : QMainWindow(parent)
{
    setWindowTitle("D-SfT Tool");
    resize(1240, 780);

    // ---------- dark terminal stylesheet ----------
    setStyleSheet(
        "QMainWindow, QWidget { background:#101216; color:#e8e8e8; font-size:13px; }"
        "QLineEdit { background:#181c23; border:1px solid #2a313c; border-radius:6px;"
        "            padding:5px 8px; color:#e8e8e8; selection-background-color:#3b82f6; }"
        "QLineEdit:focus { border-color:#3b82f6; }"
        "QLineEdit.needs-input { border:2px solid #ffd94a; }"
        "QPushButton { background:#1c222b; border:1px solid #2a313c; border-radius:6px;"
        "             padding:5px 12px; color:#e8e8e8; }"
        "QPushButton:hover { background:#242c38; }"
        "QPushButton:pressed { background:#2b3542; }"
        "QPushButton#run { background:#14351f; border-color:#1f7a3a; }"
        "QPushButton#run:hover { background:#1a4527; }"
        "QPushButton#stop { background:#3a1620; border-color:#7a1f2e; }"
        "QPushButton#stop:hover { background:#4a1c28; }"
        "QPushButton#stop:disabled, QPushButton#run:disabled { color:#556; border-color:#20262e; }"
        "QCheckBox { spacing:6px; }"
        "QTreeWidget { background:#0d1014; border:1px solid #232a34; border-radius:8px;"
        "              alternate-background-color:#11151b; }"
        "QTreeWidget::item { height:24px; }"
        "QTreeWidget::item:selected { background:#234; }"
        "QHeaderView::section { background:#161b22; color:#8a93a2; border:0;"
        "                       border-right:1px solid #232a34; padding:4px 6px; }"
        "QPlainTextEdit { background:#0a0d11; border:1px solid #232a34; border-radius:8px;"
        "                 color:#e8e8e8; font-family:'JetBrains Mono','Fira Code','DejaVu Sans Mono',monospace;"
        "                 font-size:13px; padding:4px; selection-background-color:#3b82f6; }"
        "QStatusBar { background:#0d1014; color:#9aa4b2; }"
        "QSplitter::handle { background:#1a2029; }"
        "QSpinBox { background:#181c23; border:1px solid #2a313c; border-radius:6px; padding:4px; }"
        "QGroupBox { border:1px solid #232a34; border-radius:8px; margin-top:12px; padding-top:6px; }"
        "QGroupBox::title { color:#7fd4ff; subcontrol-origin: margin; left:10px; padding:0 4px; }"
        "QToolTip { background:#181c23; color:#e8e8e8; border:1px solid #2a313c; padding:3px; }"
        "QRadioButton { spacing:6px; }");

    // ---------- top bar ----------
    auto* top = new QWidget;
    auto* tl = new QHBoxLayout(top);
    tl->setContentsMargins(8, 8, 8, 4);
    tl->setSpacing(8);

    m_addBtn = new QPushButton("+ Folder...");
    m_addBtn->setIcon(QIcon::fromTheme("folder-add"));
    m_addBtn->setToolTip("Add a folder — its runnable files are listed as a tree");
    m_addFileBtn = new QPushButton("+ File(s)...");
    m_addFileBtn->setIcon(QIcon::fromTheme("document-new"));
    m_addFileBtn->setToolTip("Add one or more runnable files directly (no folder needed)");
    m_runBtn = new QPushButton(" Run");
    m_runBtn->setIcon(QIcon::fromTheme("media-playback-start"));
    m_runBtn->setObjectName("run");
    m_runBtn->setToolTip("Run the selected entry (multi-select runs them queued)");
    m_stopBtn = new QPushButton(" Stop");
    m_stopBtn->setIcon(QIcon::fromTheme("media-playback-stop"));
    m_stopBtn->setObjectName("stop");
    m_stopBtn->setToolTip("Kill the WHOLE process tree (group + /proc walk + shim registry)");
    m_stopBtn->setEnabled(false);
    m_sandboxBtn = new QPushButton(" Limitations...");
    m_sandboxBtn->setIcon(QIcon::fromTheme("preferences-system"));
    m_sandboxBtn->setToolTip("Set disk / RAM / CPU limitations for the selected entry");
    m_sandboxBtn->setEnabled(false);   // gray until a runnable entry is selected

    m_argEdit = new QLineEdit;
    m_argEdit->setPlaceholderText("arguments passed to the program (optional)");
    m_argEdit->setClearButtonEnabled(true);
    m_autoScroll = new QCheckBox("Auto-scroll");
    m_autoScroll->setChecked(true);
    m_autoKill = new QCheckBox("Kill orphans on exit");
    m_autoKill->setChecked(true);
    m_autoKill->setToolTip("After the program exits, kill any child it left behind\n(e.g. apps that report exit code 0 but stay on screen)");

    auto* clearBtn = new QPushButton("Clear");
    clearBtn->setIcon(QIcon::fromTheme("edit-clear-all"));
    connect(clearBtn, &QPushButton::clicked, this, &MainWindow::clearOutput);

    tl->addWidget(m_addBtn);
    tl->addWidget(m_addFileBtn);
    tl->addWidget(m_runBtn);
    tl->addWidget(m_stopBtn);
    tl->addWidget(m_sandboxBtn);
    tl->addWidget(new QLabel("Args:"), 0, Qt::AlignRight);
    tl->addWidget(m_argEdit, 1);
    tl->addWidget(m_autoScroll);
    tl->addWidget(m_autoKill);
    tl->addWidget(clearBtn);

    // ---------- splitter: tree | output ----------
    auto* split = new QSplitter(Qt::Horizontal);

    m_tree = new QTreeWidget;
    m_tree->setColumnCount(4);
    m_tree->setHeaderLabels({"Name", "Type", "Size", "Limits"});
    m_tree->setRootIsDecorated(true);
    m_tree->setAlternatingRowColors(true);
    m_tree->setSelectionMode(QAbstractItemView::ExtendedSelection);  // ctrl = toggle, shift = range
    m_tree->setHorizontalScrollMode(QAbstractItemView::ScrollPerPixel);
    m_tree->setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);
    m_tree->header()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    m_tree->header()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    m_tree->header()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    m_tree->header()->setSectionResizeMode(3, QHeaderView::Fixed);
    m_tree->header()->setStretchLastSection(false);
    m_tree->header()->resizeSection(3, 130);
    m_tree->setUniformRowHeights(true);
    m_tree->setItemDelegate(new GearDelegate(m_tree));
    m_tree->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_tree->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(m_tree, &QTreeWidget::customContextMenuRequested,
            this, &MainWindow::onTreeContextMenu);

    auto* leftPane = new QWidget;
    auto* ll = new QVBoxLayout(leftPane);
    ll->setContentsMargins(0, 0, 0, 0);
    ll->setSpacing(6);
    m_searchEdit = new QLineEdit;
    m_searchEdit->setPlaceholderText("search — Enter runs top match  (fuzzy: 'kansole' finds konsole)");
    m_searchEdit->setClearButtonEnabled(true);
    if (QIcon::hasThemeIcon("edit-find-search"))
        m_searchEdit->addAction(QIcon::fromTheme("edit-find-search"), QLineEdit::LeadingPosition);
    ll->addWidget(m_searchEdit);
    ll->addWidget(m_tree, 1);

    auto* rightPane = new QWidget;
    auto* rl = new QVBoxLayout(rightPane);
    rl->setContentsMargins(0, 0, 0, 0);
    rl->setSpacing(6);

    m_out = new QPlainTextEdit;
    m_out->setReadOnly(true);
    m_out->setMaximumBlockCount(10000);
    m_out->setLineWrapMode(QPlainTextEdit::NoWrap);   // horizontal scroll in output too

    auto* inRow = new QHBoxLayout;
    inRow->setSpacing(6);
    auto* inLbl = new QLabel("stdin >");
    inLbl->setStyleSheet("color:#7fd4ff;");
    m_inEdit = new QLineEdit;
    m_inEdit->setPlaceholderText("type here to feed the running program...");
    auto* sendBtn = new QPushButton("Send");
    sendBtn->setIcon(QIcon::fromTheme("document-send"));
    inRow->addWidget(inLbl);
    inRow->addWidget(m_inEdit, 1);
    inRow->addWidget(sendBtn);

    rl->addWidget(m_out, 1);
    rl->addLayout(inRow);

    split->addWidget(leftPane);
    split->addWidget(rightPane);
    split->setStretchFactor(0, 4);
    split->setStretchFactor(1, 6);

    // ---------- bottom info board (taller: disk + ram + cpu + state) ----------
    auto* board = new QFrame;
    board->setObjectName("infoboard");
    board->setFixedHeight(40);
    board->setStyleSheet(
        "#infoboard { background:#0d1014; border-top:1px solid #232a34; }"
        "#infoboard QLabel { color:#9aa4b2; font-family:'DejaVu Sans Mono',monospace; font-size:13px; }"
        "#infoboard QLabel b { color:#e8e8e8; }");
    auto* bl = new QHBoxLayout(board);
    bl->setContentsMargins(12, 4, 12, 4);
    bl->setSpacing(18);
    m_lblState = new QLabel("state: idle");
    m_lblDisk = new QLabel("disk: 0.0 MB");
    m_lblRam = new QLabel("ram: —");
    m_lblCpu = new QLabel("cpu: —");
    auto* stretch = new QWidget;
    stretch->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
    bl->addWidget(m_lblState);
    bl->addWidget(m_lblDisk);
    bl->addWidget(m_lblRam);
    bl->addWidget(m_lblCpu);
    bl->addWidget(stretch);
    // ---------- status bar ----------

    auto* central = new QWidget;
    auto* cl = new QVBoxLayout(central);
    cl->setContentsMargins(0, 0, 0, 0);
    cl->setSpacing(0);
    cl->addWidget(top);
    cl->addWidget(split, 1);
    cl->addWidget(board);
    setCentralWidget(central);

    // ---------- connections ----------
    connect(m_addBtn, &QPushButton::clicked, this, &MainWindow::onAddPath);
    connect(m_addFileBtn, &QPushButton::clicked, this, &MainWindow::onAddFiles);
    connect(m_searchEdit, &QLineEdit::textChanged, this, &MainWindow::applyFilter);
    m_searchEdit->installEventFilter(this);
    m_tree->viewport()->installEventFilter(this);
    connect(m_runBtn, &QPushButton::clicked, this, &MainWindow::onRunClicked);
    connect(m_stopBtn, &QPushButton::clicked, this, &MainWindow::onStopClicked);
    connect(m_sandboxBtn, &QPushButton::clicked, this, &MainWindow::onSandboxForSelection);
    connect(m_tree, &QTreeWidget::itemExpanded, this, &MainWindow::onItemExpanded);
    connect(m_tree, &QTreeWidget::itemDoubleClicked, this, &MainWindow::onItemDoubleClicked);
    connect(m_tree, &QTreeWidget::itemClicked, this, &MainWindow::onTreeClicked);
    connect(m_tree, &QTreeWidget::itemSelectionChanged, this, &MainWindow::onTreeSelectionChanged);
    auto* selectAllShortcut = new QShortcut(QKeySequence::SelectAll, m_tree);
    connect(selectAllShortcut, &QShortcut::activated, m_tree, &QTreeWidget::selectAll);
    connect(sendBtn, &QPushButton::clicked, this, &MainWindow::onSendInput);
    connect(m_inEdit, &QLineEdit::returnPressed, this, &MainWindow::onSendInput);

    loadSettings();
    appendOut("D-SfT Tool ready. Add a folder or file with  + Add Path...", "#8a93a2");
    appendOut("Legend: white = program output   orange = stderr   yellow bold = activity (exec/create/delete/quota)", "#8a93a2");
}

MainWindow::~MainWindow()
{
    saveSettings();
    if (!m_jailUnit.isEmpty()) stopJailScope();   // a jailed tree must not outlive the GUI
    if (m_evNotifier) { m_evNotifier->setEnabled(false); delete m_evNotifier; }
    if (m_evFd >= 0) { ::close(m_evFd); m_evFd = -1; }
    if (!m_sockPath.isEmpty()) ::unlink(m_sockPath.toLocal8Bit().constData());
}

// ------------------------------------------------------------------ settings
QString MainWindow::configDir() const
{
    return QCoreApplication::applicationDirPath() + "/data";
}

void MainWindow::loadSettings()
{
    QFile f(configDir() + "/config.json");
    if (!f.open(QIODevice::ReadOnly)) return;
    const QJsonObject o = QJsonDocument::fromJson(f.readAll()).object();
    m_autoScroll->setChecked(o.value("autoscroll").toBool(true));
    m_autoKill->setChecked(o.value("autokill").toBool(true));
    const QJsonObject lims = o.value("limits").toObject();
    for (auto it = lims.begin(); it != lims.end(); ++it) {
        const QJsonObject l = it.value().toObject();
        Limits lim;
        lim.diskMB = (qint64)l.value("diskMB").toDouble();
        lim.diskTerminate = l.value("diskTerm").toBool(true);
        lim.diskDelete = l.value("diskDel").toBool(true);
        lim.ramMB = (qint64)l.value("ramMB").toDouble();
        lim.ramTerminate = l.value("ramTerm").toBool(true);
        lim.ramOwn = l.value("ramOwn").toBool(false);
        lim.cpuPct = l.value("cpuPct").toInt();
        lim.cpuTerminate = l.value("cpuTerm").toBool(true);
        lim.cpuOwn = l.value("cpuOwn").toBool(false);
        m_limits.insert(it.key(), lim);
    }
    const QJsonArray roots = o.value("roots").toArray();
    for (const auto& r : roots) addPathToTree(r.toString());
}

static QJsonObject limitsToJson(const Limits& l)
{
    QJsonObject o;
    o["diskMB"] = (double)l.diskMB;  o["diskTerm"] = l.diskTerminate;
    o["diskDel"] = l.diskDelete;
    o["ramMB"] = (double)l.ramMB;    o["ramTerm"] = l.ramTerminate;
    o["ramOwn"] = l.ramOwn;
    o["cpuPct"] = l.cpuPct;          o["cpuTerm"] = l.cpuTerminate;
    o["cpuOwn"] = l.cpuOwn;
    return o;
}

void MainWindow::saveSettings()
{
    QDir().mkpath(configDir());
    QJsonObject o;
    o["autoscroll"] = m_autoScroll->isChecked();
    o["autokill"] = m_autoKill->isChecked();
    QJsonArray roots;
    for (int i = 0; i < m_tree->topLevelItemCount(); ++i) {
        const QString p = m_tree->topLevelItem(i)->data(0, Qt::UserRole).toString();
        if (!p.isEmpty()) roots.append(p);
    }
    o["roots"] = roots;
    QJsonObject lims;
    for (auto it = m_limits.begin(); it != m_limits.end(); ++it)
        lims.insert(it.key(), limitsToJson(it.value()));
    o["limits"] = lims;
    QFile f(configDir() + "/config.json");
    if (f.open(QIODevice::WriteOnly)) f.write(QJsonDocument(o).toJson());
}

// ------------------------------------------------------------------ output
void MainWindow::appendOut(const QString& plain, const QString& color, bool bold)
{
    QString esc = plain.toHtmlEscaped();
    QString w = bold ? "bold" : "normal";
    m_out->appendHtml(QString("<span style=\"color:%1;font-weight:%2;white-space:pre-wrap\">%3</span>")
                          .arg(color, w, esc));
    if (m_autoScroll->isChecked()) {
        QScrollBar* sb = m_out->verticalScrollBar();
        sb->setValue(sb->maximum());
    }
}

void MainWindow::appendActivity(const QString& line)
{
    m_activity << line;
    if (m_activity.size() > 5000) m_activity.removeFirst();
    appendOut(line, "#ffd94a", true);   // yellow + bold = program activity
}

void MainWindow::clearOutput()
{
    m_out->clear();
    m_activity.clear();
}

// 10-cell block gauge for the info board (terminal-style, color by pressure:
// green < 75%, amber < 90%, red ≥ 90% of the limit)
static QString gaugeHtml(qint64 used, qint64 limit)
{
    if (limit <= 0) return QString();
    const double frac = qBound(0.0, used / double(limit), 1.0);
    const int full = int(frac * 10.0 + 0.5);
    const QString col = frac >= 0.9 ? "#f87171" : (frac >= 0.75 ? "#fbbf24" : "#4ade80");
    return QString(" <span style=\"color:%1\">%2</span><span style=\"color:#252b35\">%3</span>")
        .arg(col, QString(full, QChar(0x2588)), QString(10 - full, QChar(0x2591)));
}

void MainWindow::updateStatus()
{
    m_lblState->setText(QString("<b>state:</b> %1 &nbsp;|&nbsp; pid: %2")
                            .arg(isRunning()
                                     ? "<span style=\"color:#4ade80\">● running</span>"
                                     : "<span style=\"color:#7a8494\">○ idle</span>",
                                 m_rootPid ? QString::number(m_rootPid) : "-"));
    m_lblDisk->setText(QString("<b>disk:</b> %1%2%3")
                           .arg(m_writtenBytes / (1024.0 * 1024.0), 0, 'f', 1)
                           .arg(m_limitMB > 0 ? QString(" / %1 MB").arg(m_limitMB)
                                              : QString(" MB"))
                           .arg(gaugeHtml(m_writtenBytes, m_limitMB * 1024 * 1024)));
    QString ramMode;
    if (m_activeLimits.ramMB > 0 && m_activeLimits.ramOwn && !m_activeLimits.ramTerminate)
        ramMode = m_jailKernel ? " (kernel jail)" : " (vm-limit)";
    if (m_activeLimits.ramMB > 0)
        m_lblRam->setText(QString("<b>ram:</b> %1 MB / %2 MB%3%4")
                              .arg(m_ramBytes / (1024.0 * 1024.0), 0, 'f', 1)
                              .arg(m_activeLimits.ramMB)
                              .arg(ramMode)
                              .arg(gaugeHtml(m_ramBytes, m_activeLimits.ramMB * 1024 * 1024)));
    else
        m_lblRam->setText(QString("<b>ram:</b> %1 MB")
                              .arg(m_ramBytes / (1024.0 * 1024.0), 0, 'f', 1));
    if (m_activeLimits.cpuPct > 0)
        m_lblCpu->setText(QString("<b>cpu:</b> %1% / %2%%%3")
                              .arg(m_cpuPct).arg(m_activeLimits.cpuPct)
                              .arg(gaugeHtml(m_cpuPct, m_activeLimits.cpuPct)));
    else if (m_cpuPct > 0)
        m_lblCpu->setText(QString("<b>cpu:</b> %1%").arg(m_cpuPct));
    else
        m_lblCpu->setText("cpu: —");
}

// green + bold on the tree entry that is currently running; everything else
// keeps its normal/muted look
void MainWindow::refreshRunningMark()
{
    for (QTreeWidgetItemIterator it(m_tree); *it; ++it) {
        QTreeWidgetItem* item = *it;
        const bool runnable = item->data(0, Qt::UserRole + 1).toBool();
        const bool isRun = !m_runningPath.isEmpty() && runnable &&
                           canonical(item->data(0, Qt::UserRole).toString()) == m_runningPath;
        QFont f = item->font(0);
        f.setBold(isRun);
        item->setFont(0, f);
        if (isRun)
            item->setForeground(0, QColor("#4ade80"));
        else if (runnable)
            item->setData(0, Qt::ForegroundRole, QVariant());   // back to default
        else
            item->setForeground(0, QColor("#78828f"));
    }
}

// ------------------------------------------------------------------ tree
QTreeWidgetItem* MainWindow::findChildEntry(QTreeWidgetItem* parent, const QString& text0) const
{
    if (!parent) {
        for (int i = 0; i < m_tree->topLevelItemCount(); ++i)
            if (m_tree->topLevelItem(i)->text(0) == text0) return m_tree->topLevelItem(i);
        return nullptr;
    }
    for (int i = 0; i < parent->childCount(); ++i)
        if (parent->child(i)->text(0) == text0) return parent->child(i);
    return nullptr;
}

QTreeWidgetItem* MainWindow::makeDirItem(const QString& path)
{
    auto* it = new QTreeWidgetItem;
    QFileInfo fi(path);
    it->setText(0, fi.fileName().isEmpty() ? path : fi.fileName());
    it->setText(1, "folder");
    it->setIcon(0, QApplication::style()->standardIcon(QStyle::SP_DirIcon));
    it->setData(0, Qt::UserRole, fi.absoluteFilePath());
    it->setData(0, Qt::UserRole + 1, false);      // not runnable
    it->setData(0, Qt::UserRole + 2, (int)Runnable::None);
    it->setChildIndicatorPolicy(QTreeWidgetItem::ShowIndicator);
    it->setData(0, Qt::UserRole + 3, true);       // lazy: children not loaded yet
    return it;
}

QTreeWidgetItem* MainWindow::makeFileItem(const QString& path)
{
    auto* it = new QTreeWidgetItem;
    QFileInfo fi(path);
    QString reason;
    const bool runnable = isRunnableFile(fi, &reason);
    const QMimeType mt = iconMime(fi);          // content-sniffed, cached icon too
    it->setText(0, fi.fileName());
    it->setIcon(0, iconForMimeType(mt));
    it->setData(0, Qt::UserRole, fi.absoluteFilePath());
    it->setData(0, Qt::UserRole + 1, runnable);
    qint64 sz = fi.size();
    it->setText(2, sz < 1024 ? QString("%1 B").arg(sz) : QString("%1 KB").arg(sz / 1024));
    if (fi.suffix().compare("desktop", Qt::CaseInsensitive) == 0) {
        DesktopEntry e = parseDesktopFile(path);
        it->setText(1, "desktop entry");
        it->setForeground(1, typeArt(mt.name(), true, "desktop entry").col);
        if (e.valid) {
            it->setData(0, Qt::UserRole + 2, (int)Runnable::Desktop);
            for (const auto& a : e.actions) {
                auto* sub = new QTreeWidgetItem(it);
                sub->setText(0, "→ " + (a.name.isEmpty() ? a.id : a.name));
                sub->setText(1, "action");
                sub->setIcon(0, QApplication::style()->standardIcon(QStyle::SP_ArrowForward));
                sub->setData(0, Qt::UserRole, fi.absoluteFilePath());
                sub->setData(0, Qt::UserRole + 1, true);
                sub->setData(0, Qt::UserRole + 2, (int)Runnable::DesktopAction);
                sub->setData(0, Qt::UserRole + 3, a.execLine);
                updateSandboxColumn(sub);
            }
        }
    } else {
        // runnable → why it is one; otherwise the mime comment ("PNG image"…)
        it->setText(1, runnable ? reason : mt.comment());
        it->setForeground(1, typeArt(mt.name(), runnable, reason).col);
        it->setData(0, Qt::UserRole + 2, (int)(runnable ? Runnable::Exe : Runnable::None));
    }
    // inert data files are muted; the running entry glows green + bold
    if (!m_runningPath.isEmpty() && canonical(fi.absoluteFilePath()) == m_runningPath) {
        it->setForeground(0, QColor("#4ade80"));
        QFont f = it->font(0);
        f.setBold(true);
        it->setFont(0, f);
    } else if (!runnable) {
        it->setForeground(0, QColor("#78828f"));
    }
    updateSandboxColumn(it);
    return it;
}

void MainWindow::updateSandboxColumn(QTreeWidgetItem* it)
{
    const QString p = canonical(it->data(0, Qt::UserRole).toString());
    const Limits l = m_limits.value(p);
    it->setText(3, l.any() ? l.summary() : QString());
    it->setToolTip(3, l.any() ? QString("limitations: %1").arg(l.summary())
                              : "no limits — click the gear to set some");
}

void MainWindow::populateDirItem(QTreeWidgetItem* dirItem)
{
    if (!dirItem->data(0, Qt::UserRole + 3).toBool()) return;   // already populated
    dirItem->setData(0, Qt::UserRole + 3, false);
    const QString path = dirItem->data(0, Qt::UserRole).toString();
    QDir dir(path);
    const QFileInfoList entries =
        dir.entryInfoList(QDir::AllEntries | QDir::NoDotAndDotDot | QDir::Hidden,
                          QDir::DirsFirst | QDir::Name);
    for (const QFileInfo& fi : entries) {
        const QString existing = fi.fileName();
        if (findChildEntry(dirItem, existing)) continue;
        if (fi.isDir()) {
            dirItem->addChild(makeDirItem(fi.absoluteFilePath()));
        } else {
            // every file is listed: runnables normal, non-runnables muted
            // with their content-type icon (they can't be run)
            dirItem->addChild(makeFileItem(fi.absoluteFilePath()));
        }
    }
    if (dirItem->childCount() == 0)
        dirItem->setText(1, "folder (empty)");
}

bool MainWindow::addPathToTree(const QString& rawPath)
{
    QFileInfo fi(rawPath);
    if (!fi.exists()) {
        appendOut("not found: " + rawPath, "#ff8080");
        return false;
    }
    const QString abs = canonical(rawPath);
    const QString label = fi.fileName().isEmpty() ? abs : fi.fileName();

    // Re-adding an existing root? Just focus it.
    for (int i = 0; i < m_tree->topLevelItemCount(); ++i)
        if (canonical(m_tree->topLevelItem(i)->data(0, Qt::UserRole).toString()) == abs) {
            m_tree->setCurrentItem(m_tree->topLevelItem(i));
            return true;
        }

    QTreeWidgetItem* it;
    if (fi.isDir()) {
        it = makeDirItem(abs);
        populateDirItem(it);          // depth-1 now; deeper on expand
    } else {
        it = makeFileItem(abs);
    }
    m_tree->addTopLevelItem(it);
    saveSettings();
    return true;
}

void MainWindow::onAddFiles()
{
    const QStringList files = QFileDialog::getOpenFileNames(
        this, "Add runnable file(s)", QString(), "All files (*)");
    int added = 0;
    for (const QString& f : files)
        if (addPathToTree(f)) ++added;
    if (added) {
        appendOut(QString("added %1 file(s) to explorer").arg(added), "#7fd4ff");
        m_tree->expandAll();
        if (!m_searchEdit->text().isEmpty()) applyFilter();
    }
}

bool MainWindow::eventFilter(QObject* obj, QEvent* ev)
{
    // --- search box: Enter runs the top match, Esc clears ---
    if (obj == m_searchEdit && ev->type() == QEvent::KeyPress) {
        auto* ke = static_cast<QKeyEvent*>(ev);
        if (ke->key() == Qt::Key_Return || ke->key() == Qt::Key_Enter) {
            QTreeWidgetItem* it = m_tree->currentItem();
            if (it && it->data(0, Qt::UserRole + 1).toBool() && !isRunning()) {
                const Runnable r = runnableForItem(it);
                m_searchEdit->clear();
                runPath(r.path, m_argEdit->text(),
                        r.kind == Runnable::DesktopAction ? r.actionExec : QString());
            }
            return true;
        }
        if (ke->key() == Qt::Key_Escape) {
            m_searchEdit->clear();
            return true;
        }
    }

    // --- tree: Alt+click = select the RANGE from the current item to here ---
    if (obj == m_tree->viewport() && ev->type() == QEvent::MouseButtonPress) {
        auto* me = static_cast<QMouseEvent*>(ev);
        if (me->modifiers().testFlag(Qt::AltModifier)) {
            QTreeWidgetItem* target = m_tree->itemAt(me->pos());
            if (target) {
                QList<QTreeWidgetItem*> flat;
                flatVisible(flat, nullptr);
                QTreeWidgetItem* anchor = m_tree->currentItem();
                int a = flat.indexOf(anchor);
                int b = flat.indexOf(target);
                if (a < 0) a = b;
                if (b < 0) b = a;
                if (a > b) std::swap(a, b);
                m_tree->clearSelection();
                for (int i = a; i <= b && i < flat.size(); ++i) flat[i]->setSelected(true);
                m_tree->setCurrentItem(target);
                return true;   // consume: don't let the default single-select fire
            }
        }
    }
    return QMainWindow::eventFilter(obj, ev);
}

// visible (expanded) items in display order — for Alt range selection
void MainWindow::flatVisible(QList<QTreeWidgetItem*>& out, QTreeWidgetItem* parent) const
{
    const int n = parent ? parent->childCount() : m_tree->topLevelItemCount();
    for (int i = 0; i < n; ++i) {
        QTreeWidgetItem* it = parent ? parent->child(i) : m_tree->topLevelItem(i);
        out.append(it);
        if (it->isExpanded()) flatVisible(out, it);
    }
}

void MainWindow::applyFilter()
{
    const QString q = m_searchEdit->text().trimmed();

    // rank, hide non-matching, auto-expand ancestors of matches
    struct Best { QTreeWidgetItem* it = nullptr; int score = -1; };
    Best best;

    std::function<int(QTreeWidgetItem*)> walk = [&](QTreeWidgetItem* it) -> int {
        // deep-populate pending folders so the search sees the whole tree
        if (it->data(0, Qt::UserRole + 3).toBool())
            populateDirItem(it);

        int own = -1;
        if (!q.isEmpty()) {
            const QString path = it->data(0, Qt::UserRole).toString();
            if (q.contains('/'))
                own = fuzzyScore(path, q);
            else {
                own = fuzzyScore(it->text(0), q);
                const QString stem = QFileInfo(it->text(0)).completeBaseName();
                if (!stem.isEmpty() && stem != it->text(0))
                    own = qMax(own, fuzzyScore(stem, q));
            }
        } else {
            own = 1000;   // no query: everything visible
        }

        int childBest = -1;
        for (int c = 0; c < it->childCount(); ++c)
            childBest = qMax(childBest, walk(it->child(c)));

        const bool vis = (own >= 0) || (childBest >= 0);
        it->setHidden(!vis);
        if (vis && childBest >= 0) it->setExpanded(true);

        if (vis && own > best.score) { best.score = own; best.it = it; }
        return vis ? qMax(own, childBest) : -1;
    };
    for (int i = 0; i < m_tree->topLevelItemCount(); ++i) walk(m_tree->topLevelItem(i));

    if (!q.isEmpty() && best.it) {
        m_tree->setCurrentItem(best.it);
        m_tree->scrollToItem(best.it);
    }
}

void MainWindow::onItemExpanded(QTreeWidgetItem* it)
{
    if (it->data(0, Qt::UserRole + 3).toBool() &&
        (it->text(1) == "folder" || it->text(1).startsWith("folder")))
        populateDirItem(it);
}

void MainWindow::onAddPath()
{
    QString p = QFileDialog::getExistingDirectory(this, "Add folder (its runnable files will be listed)");
    if (p.isEmpty()) {
        p = QFileDialog::getOpenFileName(this, "Add a runnable file", QString(),
                                         "All files (*)");
    }
    if (p.isEmpty()) return;
    if (addPathToTree(p)) {
        appendOut("added to explorer: " + p, "#7fd4ff");
        m_tree->expandAll();
    }
}

// ------------------------------------------------------------------ limitations dialog
void MainWindow::openSandboxDialog(QTreeWidgetItem* it)
{
    if (!it) return;
    const QString path = canonical(it->data(0, Qt::UserRole).toString());
    if (path.isEmpty()) return;
    if (!it->data(0, Qt::UserRole + 1).toBool()) {
        appendOut("limitations: only runnable entries can be limited", "#8a93a2");
        return;
    }
    Limits cur = m_limits.value(path);

    QDialog dlg(this);
    dlg.setWindowTitle("Limitations config — " + it->text(0));
    dlg.setMinimumWidth(460);
    auto* lay = new QVBoxLayout(&dlg);

    // ---------------- disk ----------------
    auto* diskBox = new QGroupBox("Disk limit");
    auto* dv = new QVBoxLayout(diskBox);
    auto* diskRow = new QHBoxLayout;
    diskRow->addWidget(new QLabel("Max disk it may write:"));
    auto* diskSpin = new QSpinBox;
    diskSpin->setRange(0, 1048576);
    diskSpin->setSuffix(" MB");
    diskSpin->setValue((int)cur.diskMB);
    diskRow->addWidget(diskSpin);
    diskRow->addStretch(1);
    dv->addLayout(diskRow);
    auto* diskTerm = new QCheckBox("Terminate? (kill the program tree when it passes the limit)");
    diskTerm->setChecked(cur.diskTerminate);
    dv->addWidget(diskTerm);
    auto* diskDel = new QCheckBox("Delete & limit disk usage? (delete everything it created, instantly)");
    diskDel->setChecked(cur.diskDelete);
    dv->addWidget(diskDel);
    lay->addWidget(diskBox);

    // ---------------- ram ----------------
    auto* ramBox = new QGroupBox("RAM limit");
    auto* rv = new QVBoxLayout(ramBox);
    auto* ramRow = new QHBoxLayout;
    ramRow->addWidget(new QLabel("Max RAM it may use:"));
    auto* ramSpin = new QSpinBox;
    ramSpin->setRange(0, 1048576);
    ramSpin->setSuffix(" MB");
    ramSpin->setValue((int)cur.ramMB);
    ramRow->addWidget(ramSpin);
    ramRow->addStretch(1);
    rv->addLayout(ramRow);
    auto* ramTerm = new QRadioButton("Terminate — kill the whole tree when it passes the limit");
    ramTerm->setToolTip("System-Monitor semantics: when the tree's REAL resident RAM (VmRSS)\n"
                        "passes the limit, it and everything it spawned dies.");
    auto* ramOwn = new QRadioButton("Own sandbox — real kernel jail: it can never use more RAM than this");
    ramOwn->setToolTip("cgroup v2 scope (memory.max): allocations FAIL or the kernel OOM-kills it —\n"
                       "raw mmap and static binaries included, exactly like on a constrained PC.\n"
                       "Falls back to RLIMIT_AS (virtual memory, stricter) without a systemd user session.");
    auto* ramWatch = new QRadioButton("Watch only — take no action, just show the live meter");
    // exactly ONE mode (the old two-checkbox UI could end up with the
    // impossible "terminate AND sandbox" combo, and its show/hide trick
    // glitched the group box layout mid-dialog)
    if (cur.ramTerminate) ramTerm->setChecked(true);
    else if (cur.ramOwn) ramOwn->setChecked(true);
    else ramWatch->setChecked(true);
    rv->addWidget(ramTerm);
    rv->addWidget(ramOwn);
    rv->addWidget(ramWatch);
    lay->addWidget(ramBox);

    // ---------------- cpu ----------------
    auto* cpuBox = new QGroupBox("CPU limit");
    auto* cv = new QVBoxLayout(cpuBox);
    auto* cpuRow = new QHBoxLayout;
    cpuRow->addWidget(new QLabel("Max CPU it may use (% of ALL cores — like System Monitor):"));
    auto* cpuSpin = new QSpinBox;
    cpuSpin->setRange(0, 100);
    cpuSpin->setSuffix(" %");
    cpuSpin->setValue(cur.cpuPct);
    cpuRow->addWidget(cpuSpin);
    cpuRow->addStretch(1);
    cv->addLayout(cpuRow);
    auto* cpuTerm = new QRadioButton("Terminate — kill the whole tree when it stays over the limit");
    cpuTerm->setToolTip("Sustained (2 meter ticks) above the limit → the tree dies.");
    auto* cpuOwn = new QRadioButton("Own sandbox — throttle it to N% of ALL cores (like a slower PC)");
    cpuOwn->setToolTip("SIGSTOP/SIGCONT duty-cycling keeps the tree near the limit.");
    auto* cpuWatch = new QRadioButton("Watch only — take no action, just show the live meter");
    if (cur.cpuTerminate) cpuTerm->setChecked(true);
    else if (cur.cpuOwn) cpuOwn->setChecked(true);
    else cpuWatch->setChecked(true);
    cv->addWidget(cpuTerm);
    cv->addWidget(cpuOwn);
    cv->addWidget(cpuWatch);
    lay->addWidget(cpuBox);

    lay->addWidget(new QLabel("0 = unlimited / off."));
    auto* bb = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
    connect(bb, &QDialogButtonBox::accepted, &dlg, &QDialog::accept);
    connect(bb, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);
    lay->addWidget(bb);
    if (dlg.exec() != QDialog::Accepted) return;

    Limits l;
    l.diskMB = diskSpin->value();
    l.diskTerminate = diskTerm->isChecked();
    l.diskDelete = diskDel->isChecked();
    l.ramMB = ramSpin->value();
    l.ramTerminate = ramTerm->isChecked();
    l.ramOwn = ramOwn->isChecked();
    l.cpuPct = cpuSpin->value();
    l.cpuTerminate = cpuTerm->isChecked();
    l.cpuOwn = cpuOwn->isChecked();
    setLimitsFor(path, l);
    appendOut(QString("limitations for %1: %2").arg(it->text(0),
              l.any() ? l.summary() : QString("unlimited")), "#7fd4ff");
}

void MainWindow::setLimitsFor(const QString& path, const Limits& l)
{
    if (l.any()) m_limits.insert(path, l); else m_limits.remove(path);
    for (int i = 0; i < m_tree->topLevelItemCount(); ++i) {
        QTreeWidgetItem* top = m_tree->topLevelItem(i);
        QList<QTreeWidgetItem*> stack{top};
        while (!stack.isEmpty()) {
            QTreeWidgetItem* cur = stack.takeFirst();
            if (canonical(cur->data(0, Qt::UserRole).toString()) == path) updateSandboxColumn(cur);
            for (int c = 0; c < cur->childCount(); ++c) stack << cur->child(c);
        }
    }
    saveSettings();
}

void MainWindow::setQuotaFor(const QString& path, qint64 mb)
{
    Limits l = m_limits.value(path);
    l.diskMB = mb;
    setLimitsFor(path, l);
}

void MainWindow::onSandboxForSelection()
{
    openSandboxDialog(m_tree->currentItem());
}

void MainWindow::onTreeClicked(QTreeWidgetItem* it, int col)
{
    if (col == 3 && it && it->data(0, Qt::UserRole + 1).toBool())
        openSandboxDialog(it);   // gear column click
}

void MainWindow::onTreeContextMenu(const QPoint& pos)
{
    QTreeWidgetItem* it = m_tree->itemAt(pos);
    QMenu menu(this);
    connect(menu.addAction("+ Add Folder..."), &QAction::triggered, this, &MainWindow::onAddPath);
    connect(menu.addAction("+ Add File(s)..."), &QAction::triggered, this, &MainWindow::onAddFiles);
    menu.addSeparator();
    if (it) {
        if (it->data(0, Qt::UserRole + 1).toBool()) {
            connect(menu.addAction("▶ Run"), &QAction::triggered, this, &MainWindow::onRunClicked);
            connect(menu.addAction("⚙ Limitations..."), &QAction::triggered,
                    this, [this, it]() { openSandboxDialog(it); });
        }
        if (it->childCount())
            connect(menu.addAction("Collapse subtree"), &QAction::triggered,
                    this, [this, it]() { it->setExpanded(false); });
        connect(menu.addAction("Remove from explorer"), &QAction::triggered, this, [this, it]() {
            delete it;                     // removes the root (and its children)
            saveSettings();
        });
    }
    connect(menu.addAction("Select all (Ctrl+A)"), &QAction::triggered,
            m_tree, &QTreeWidget::selectAll);
    connect(menu.addAction("Clear all"), &QAction::triggered, this, &MainWindow::onClearAll);
    menu.exec(m_tree->viewport()->mapToGlobal(pos));
}

// remove every root from the explorer (+ their limitation sets)
void MainWindow::onClearAll()
{
    m_tree->clear();
    m_limits.clear();
    onTreeSelectionChanged();      // re-evaluate the Limitations button state
    saveSettings();
    appendOut("explorer cleared", "#8a93a2");
}

// the Limitations button only makes sense for a runnable selection
void MainWindow::onTreeSelectionChanged()
{
    QTreeWidgetItem* it = m_tree->currentItem();
    const bool runnable = it && it->data(0, Qt::UserRole + 1).toBool();
    m_sandboxBtn->setEnabled(runnable);
    m_sandboxBtn->setToolTip(runnable
        ? "Set disk / RAM / CPU limitations for the selected entry"
        : "Select a runnable entry first");
}

void MainWindow::onItemDoubleClicked(QTreeWidgetItem* it, int col)
{
    Q_UNUSED(col);
    if (!it || !it->data(0, Qt::UserRole + 1).toBool()) return;
    if (isRunning()) { appendOut("already running — press ■ Stop first", "#ff8080"); return; }
    const Runnable r = runnableForItem(it);
    runPath(r.path, m_argEdit->text(), r.kind == Runnable::DesktopAction ? r.actionExec : QString());
}

Runnable MainWindow::runnableForItem(QTreeWidgetItem* it) const
{
    Runnable r;
    if (!it) return r;
    r.path = it->data(0, Qt::UserRole).toString();
    const int k = it->data(0, Qt::UserRole + 2).toInt();
    r.kind = (Runnable::Kind)k;
    r.actionExec = it->data(0, Qt::UserRole + 3).toString();
    r.actionName = it->text(0);
    r.display = it->text(0);
    return r;
}

// ------------------------------------------------------------------ misc UI
void MainWindow::onSendInput()
{
    const QString t = m_inEdit->text();
    if (t.isEmpty()) return;
    sendStdin(t);
    m_inEdit->clear();
    m_inEdit->setProperty("needsInput", false);
    m_inEdit->style()->unpolish(m_inEdit);
    m_inEdit->style()->polish(m_inEdit);
}

void MainWindow::sendStdin(const QString& text)
{
    if (m_proc.state() != QProcess::NotRunning) {
        appendOut("> " + text, "#7fd4ff");
        m_proc.write(text.toUtf8() + '\n');
    } else {
        appendOut("no running program to receive input", "#8a93a2");
    }
}

void MainWindow::logSelectInfo()
{
    QTreeWidgetItem* it = m_tree->currentItem();
    if (!it) return;
    appendOut("selected: " + it->data(0, Qt::UserRole).toString(), "#8a93a2");
}

void MainWindow::prepareForTest()
{
    clearOutput();
    m_runningPath.clear();
    if (!m_jailUnit.isEmpty()) {                  // hygiene: no stale jail scope between tests
        stopJailScope();
        m_jailUnit.clear();
        m_jailCgroup.clear();
        m_jailKernel = false;
    }
    m_quotaFired = false;
    m_quotaCleanupDone = false;
    m_orphans = 0;
    m_exitLine.clear();
    m_registry.clear();
    m_writtenBytes = 0;
    m_rootPid = 0;
    m_runDisplay.clear();
}
