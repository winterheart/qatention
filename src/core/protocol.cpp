#include "protocol.h"

#include <QRegularExpression>
#include <QXmlStreamReader>
#include <QtEndian>

#include <qversionnumber.h>

namespace aten {
static void require(const QByteArray& b, qsizetype p, qsizetype n)
{
    if (p < 0 || p > b.size() || n > b.size() - p) {
        throw Error("Truncated protocol record");
    }
}

quint16 be16(const QByteArray& b, qsizetype p)
{
    require(b, p, 2);
    return qFromBigEndian<quint16>(b.constData() + p);
}

quint32 be32(const QByteArray& b, qsizetype p)
{
    require(b, p, 4);
    return qFromBigEndian<quint32>(b.constData() + p);
}

void put16(QByteArray& b, qsizetype p, quint16 v)
{
    require(b, p, 2);
    qToBigEndian(v, b.data() + p);
}

void put32(QByteArray& b, qsizetype p, quint32 v)
{
    require(b, p, 4);
    qToBigEndian(v, b.data() + p);
}

QByteArray keyEvent(quint32 usage, bool down)
{
    QByteArray b(18, 0);
    b[0] = 4;
    b[2] = down ? 1 : 0;
    put32(b, 5, usage);
    return b;
}

QByteArray pointerEvent(int x, int y, int buttons)
{
    QByteArray b(18, 0);
    b[0] = 5;
    b[2] = char(buttons);
    put16(b, 3, quint16(x));
    put16(b, 5, quint16(y));
    return b;
}

QByteArray updateRequest(QSize size, bool incremental)
{
    QByteArray b(10, 0);
    b[0] = 3;
    b[1] = incremental ? 1 : 0;
    put16(b, 6, quint16(size.width()));
    put16(b, 8, quint16(size.height()));
    return b;
}

QByteArray credentials(const QString& user, const QString& password)
{
    auto field = [](const QString& s)
    {
        if (s.isEmpty() || s.size() > 24) {
            throw Error(
                "KVM credentials must contain 1 to 24 ASCII characters");
        }
        for (auto c: s) {
            if (c.unicode() < 32 || c.unicode() > 126) {
                throw Error("KVM credentials must be ASCII");
            }
        }
        auto b = s.toLatin1();
        b.append(QByteArray(24 - b.size(), 0));
        return b;
    };
    return field(user) + field(password);
}

static QVersionNumber parseResources(QXmlStreamReader& reader)
{
    QRegularExpression re("iKVM__V(\\d+).(\\d+).(\\d+).0x0.jar");

    while (!(reader.isEndElement() && reader.name() == "resources")) {
        reader.readNext();
        if (reader.name() == u"jar"
            && reader.attributes().hasAttribute(u"href")) {
            QString href =
                reader.attributes().value("href").toString();
            QRegularExpressionMatch match = re.match(reader.attributes()
                .value("href").toString());
            if (match.hasMatch()) {
                return QVersionNumber(match.captured(1).toInt(),
                    match.captured(2).toInt(),
                    match.captured(3).toInt()
                    );
            }
        }
    }
    return QVersionNumber(0, 0, 0);
}

Launch parseJnlp(const QByteArray& xml)
{
    if (xml.size() > 1024LL * 1024) {
        throw Error("JNLP is too large");
    }
    QXmlStreamReader reader(xml);
    QStringList args;
    QVersionNumber mainJarVersion(0, 0, 0);
    while (!reader.atEnd()) {
        reader.readNext();
        if (reader.isDTD()) {
            throw Error("JNLP document types are not supported");
        }
        QString test = reader.name().toString();
        if (reader.isStartElement() && reader.name() == u"resources" &&
            reader.attributes().size() == 0) {
            mainJarVersion = parseResources(reader);
        }
        if (reader.isStartElement() && reader.name() == u"argument") {
            args << reader.readElementText().trimmed();
        }
    }
    if (reader.hasError() || args.size() < 10) {
        throw Error("Invalid ATEN launch JNLP");
    }
    if (mainJarVersion == QVersionNumber(0, 0, 0)) {
        throw Error("Unknown version of iKVM.jar");
    }

    int index = 0;
    if (mainJarVersion >= QVersionNumber(1, 69, 40)) {
        // Starting from 1.69.40,
        // first 9 entries are URI and platform-specific JARs.
        index = 10;
    }
    if (args[index + 8] != "0" && args[index + 8] != "1") {
        throw Error("Invalid JNLP TLS flag");
    }

    Launch l;
    l.host = args[index + 0];
    l.user = args[index + 1];
    l.password = args[index + 2];
    l.tls = args[index + 8] == "1";
    bool ok = false;
    int port = args[l.tls ? index + 9 : index + 4].toInt(&ok);
    if (!ok || port < 1 || port > 65535 || l.host.isEmpty()) {
        throw Error("Invalid JNLP endpoint");
    }
    l.port = quint16(port);
    int mediaIndex;
    if (mainJarVersion >= QVersionNumber(1, 69, 38)) {
        mediaIndex = l.tls ? index + 10 : index + 5;
    } else {
        // In 1.69.30 arg[10] is Language
        mediaIndex = index + 5;
    }
    if (args.size() > mediaIndex) {
        int media = args[mediaIndex].toInt();
        if (media > 0 && media <= 65535) {
            l.mediaPort = quint16(media);
        }
    }
    credentials(l.user, l.password);
    return l;
}
}   // namespace aten
