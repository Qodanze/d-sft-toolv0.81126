#pragma once
#include <QString>
#include <QStringList>
#include <QList>

// Parser for freedesktop .desktop entries (Linux). Understands:
//   [Desktop Entry] Name/Exec/Terminal/Icon/GenericName
//   [Desktop Action <id>] sub-entries (runnable variants)
//   Field codes  %f %F %u %U %d %D %n %N %i %c %k %v %m
//   Flatpak file-forwarding wrappers: "@@u %u @@" and "@@ %F @@"
struct DesktopEntry {
    QString path;
    QString name, genericName, icon, execLine;
    bool terminal = false;
    bool valid = false;

    struct Action { QString id; QString name; QString execLine; };
    QList<Action> actions;

    // Tokenize Exec: strip field codes, unwrap flatpak @@...@@ forwarding,
    // substitute the first file/url code with `args` when given.
    QStringList execTokens(const QString& args = QString()) const;
};

DesktopEntry parseDesktopFile(const QString& path);

// Shell-ish tokenizer (quotes + backslash escapes) for the Args box.
QStringList splitArgs(const QString& s);
