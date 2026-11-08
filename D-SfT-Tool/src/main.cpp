#include <QApplication>
#include <QIcon>
#include <QPainter>
#include <QPixmap>
#include "mainwindow.h"

// Window icon: use the desktop theme's icon when available, else draw a
// small ">_" terminal glyph so the tool never shows a blank/generic icon.
static QIcon dsftIcon()
{
    for (const char* name : {"applications-development", "utilities-terminal", "system-run"})
        if (QIcon::hasThemeIcon(name))
            return QIcon::fromTheme(name);
    QPixmap pm(64, 64);
    pm.fill(Qt::transparent);
    QPainter p(&pm);
    p.setRenderHint(QPainter::Antialiasing);
    p.setBrush(QColor("#101216"));
    p.setPen(QPen(QColor("#2a313c"), 2));
    p.drawRoundedRect(2, 2, 60, 60, 12, 12);
    p.setPen(QPen(QColor("#ffd94a"), 3, Qt::SolidLine, Qt::RoundCap));
    p.drawLine(16, 24, 27, 35);      // ">"
    p.drawLine(27, 35, 16, 46);
    p.drawLine(33, 47, 47, 47);      // "_"
    p.end();
    return QIcon(pm);
}

int main(int argc, char** argv)
{
    const bool selftest = (argc > 1 && QByteArray(argv[1]) == "--selftest");
    if (selftest)
        qputenv("QT_QPA_PLATFORM", "offscreen");

    QApplication app(argc, argv);
    QApplication::setApplicationName("D-SfT Tool");
    QApplication::setOrganizationName("DSfT");
    QApplication::setWindowIcon(dsftIcon());

    if (selftest)
        return DSfT::runSelfTest();

    MainWindow w;
    w.show();
    return app.exec();
}
