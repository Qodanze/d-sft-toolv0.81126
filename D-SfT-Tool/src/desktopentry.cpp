#include "desktopentry.h"
#include <QFile>
#include <QTextStream>
#include <QFileInfo>

QStringList splitArgs(const QString& s)
{
    QStringList out;
    QString cur;
    bool have = false, inS = false, inD = false;
    for (int i = 0; i < s.size(); ++i) {
        const QChar c = s.at(i);
        if (inS) {
            if (c == '\'') inS = false; else cur += c;
            continue;
        }
        if (inD) {
            if (c == '"') inD = false;
            else if (c == '\\' && i + 1 < s.size()) cur += s.at(++i);
            else cur += c;
            continue;
        }
        if (c == '\'') { inS = true; have = true; continue; }
        if (c == '"')  { inD = true; have = true; continue; }
        if (c == '\\' && i + 1 < s.size()) { cur += s.at(++i); have = true; continue; }
        if (c.isSpace()) {
            if (have) { out << cur; cur.clear(); have = false; }
            continue;
        }
        cur += c; have = true;
    }
    if (have) out << cur;
    return out;
}

// Raw freedesktop Exec tokenizer: ' and " quoting, backslash escapes.
static QStringList rawExecTokens(const QString& s)
{
    QStringList out;
    QString cur;
    bool have = false;
    int i = 0;
    const int n = s.size();
    while (i < n) {
        const QChar c = s.at(i);
        if (c.isSpace()) {
            if (have) { out << cur; cur.clear(); have = false; }
            ++i; continue;
        }
        if (c == '\'') {
            ++i;
            while (i < n && s.at(i) != '\'') cur += s.at(i++);
            if (i < n) ++i;
            have = true; continue;
        }
        if (c == '"') {
            ++i;
            while (i < n && s.at(i) != '"') {
                if (s.at(i) == '\\' && i + 1 < n) {
                    const QChar nx = s.at(i + 1);
                    if (nx == '$' || nx == '"' || nx == '\\' || nx == '`') { cur += nx; i += 2; }
                    else cur += s.at(i++);
                } else cur += s.at(i++);
            }
            if (i < n) ++i;
            have = true; continue;
        }
        if (c == '\\') {
            if (i + 1 < n) { cur += s.at(i + 1); i += 2; have = true; }
            else ++i;
            continue;
        }
        cur += c; ++i; have = true;
    }
    if (have) out << cur;
    return out;
}

QStringList DesktopEntry::execTokens(const QString& args) const
{
    const QStringList toks = rawExecTokens(execLine);
    const QStringList argToks = splitArgs(args);
    QStringList out;
    bool substituted = false;
    static const QString fileCodes = "fFuU";
    static const QString allCodes  = "fFuUdDnNickvm";

    int i = 0;
    while (i < toks.size()) {
        const QString t = toks.at(i);
        // Flatpak forwarding wrapper: "@@u %u @@" or "@@ %F @@"
        if (t.startsWith("@@")) {
            if (t == "@@") {                    // opening "@@" -> skip to closing "@@"
                ++i;
                while (i < toks.size() && toks.at(i) != "@@") ++i;
                ++i;
                continue;
            }
            ++i;                                // "@@u"-style opening token
            if (i < toks.size() && toks.at(i).startsWith('%')) {
                if (!substituted && !argToks.isEmpty()) { out << argToks; substituted = true; }
                ++i;
            }
            if (i < toks.size() && toks.at(i) == "@@") ++i;
            continue;
        }
        // Field codes
        if (t.size() == 2 && t.at(0) == '%' && allCodes.contains(t.at(1))) {
            const QChar code = t.at(1);
            if (!substituted && !argToks.isEmpty() && fileCodes.contains(code)) {
                out << argToks; substituted = true;
            }
            ++i; continue;                      // drop all field codes
        }
        out << t;
        ++i;
    }
    if (!argToks.isEmpty() && !substituted) out << argToks;
    return out;
}

DesktopEntry parseDesktopFile(const QString& path)
{
    DesktopEntry e;
    e.path = path;
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly | QIODevice::Text))
        return e;

    enum Section { None, Entry, Action } sect = None;
    DesktopEntry::Action curAction;
    QTextStream ts(&f);
    while (!ts.atEnd()) {
        QString line = ts.readLine().trimmed();
        if (line.isEmpty() || line.startsWith('#')) continue;
        if (line.startsWith('[')) {
            if (sect == Action && !curAction.id.isEmpty()) e.actions << curAction;
            curAction = DesktopEntry::Action();
            const QString g = line.mid(1, line.indexOf(']') > 0 ? line.indexOf(']') - 1 : -1);
            if (g == "Desktop Entry") sect = Entry;
            else if (g.startsWith("Desktop Action ")) {
                sect = Action;
                curAction.id = g.mid(QString("Desktop Action ").size());
            } else sect = None;
            continue;
        }
        const int eq = line.indexOf('=');
        if (eq <= 0) continue;
        const QString key = line.left(eq).trimmed();
        const QString val = line.mid(eq + 1);
        if (sect == Entry) {
            if (key == "Name") e.name = val;
            else if (key == "GenericName") e.genericName = val;
            else if (key == "Icon") e.icon = val;
            else if (key == "Exec") e.execLine = val;
            else if (key == "Terminal") e.terminal = (val.trimmed().compare("true", Qt::CaseInsensitive) == 0);
        } else if (sect == Action) {
            if (key == "Name") curAction.name = val;
            else if (key == "Exec") curAction.execLine = val;
        }
    }
    if (sect == Action && !curAction.id.isEmpty()) e.actions << curAction;
    e.valid = !e.execLine.isEmpty();
    if (e.name.isEmpty()) e.name = QFileInfo(path).completeBaseName();
    return e;
}
