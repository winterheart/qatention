#include "core/debuglog.h"
#include "core/decoder.h"
#include "core/media.h"
#include "core/profiles.h"
#include "core/protocol.h"
#include "core/session.h"

#include <QFile>
#include <QMessageAuthenticationCode>
#include <QSignalSpy>
#include <QSslConfiguration>
#include <QSslKey>
#include <QTcpServer>
#include <QTcpSocket>
#include <QTemporaryDir>
#include <QtEndian>
#include <QtTest>

using namespace aten;

static QByteArray hermon(int w, int h, quint16 pixel)
{
    QByteArray p(10 + w * h * 2, 0);
    p[0] = 1;
    put32(p, 6, quint32(p.size()));
    for (int i = 10; i < p.size(); i += 2) {
        qToLittleEndian(pixel, p.data() + i);
    }
    return p;
}

static QByteArray frameMessage(const QByteArray& p, int w, int h)
{
    QByteArray b(24, 0);
    put16(b, 2, 1);
    put16(b, 8, w);
    put16(b, 10, h);
    put32(b, 20, quint32(p.size()));
    return b + p;
}

class WebBmc: public QTcpServer
{
public:
    int logins = 0, logouts = 0, mediaRequests = 0;
    bool reject = false;
    quint16 consolePort = 0;
    QSslKey key;
    QSslCertificate cert;
    QList<QSslCertificate> chain;

    void incomingConnection(qintptr descriptor) override
    {
        auto* socket = new QSslSocket(this);
        socket->setSocketDescriptor(descriptor);
        socket->setLocalCertificate(cert);
        if (!chain.isEmpty()) {
            socket->setLocalCertificateChain(chain);
        }
        socket->setPrivateKey(key);
        socket->setPeerVerifyMode(QSslSocket::VerifyNone);
        auto data = std::make_shared<QByteArray>();
        connect(
            socket,
            &QSslSocket::readyRead,
            this,
            [this, socket, data]
            {
                *data += socket->readAll();
                if (*data == mediaControl(8)) {
                    ++mediaRequests;
                    data->clear();
                    return;
                }
                if (!data->contains("\r\n\r\n")) {
                    return;
                }
                if (data->startsWith("POST") &&
                    !data->contains("pwd=password")) {
                    return;
                }
                QByteArray body, headers;
                if (data->startsWith("GET /cgi/logout.cgi")) {
                    ++logouts;
                }
                if (data->startsWith("POST /cgi/login.cgi")) {
                    ++logins;
                    if (!reject) {
                        headers = "Set-Cookie: SID=test; Path=/\r\n";
                    }
                } else if (data->startsWith("GET /cgi/url_redirect")) {
                    body =
                        "<jnlp><application-desc><argument>127.0.0.1</"
                        "argument><argument>token" +
                        QByteArray::number(logins) +
                        "</argument><argument>pass</argument><argument>host</"
                        "argument><argument>" +
                        QByteArray::number(consolePort) +
                        "</argument><argument>623</argument><argument>1</"
                        "argument><argument>1</argument><argument>0</"
                        "argument><argument>5900</argument></"
                        "application-desc></jnlp>";
                }
                socket->write(
                    "HTTP/1.1 200 OK\r\n" + headers +
                    "Content-Length: " + QByteArray::number(body.size()) +
                    "\r\nConnection: close\r\n\r\n" + body);
                socket->disconnectFromHost();
            });
        connect(
            socket,
            &QSslSocket::disconnected,
            socket,
            &QObject::deleteLater);
        socket->startServerEncryption();
    }
};

class CoreTests: public QObject
{
    Q_OBJECT
private slots:

    void consoleCertificatePinning()
    {
        auto load = [](const char* name)
        {
            QFile f(QString(":/tls/tests/certificates/") + name);
            f.open(QIODevice::ReadOnly);
            return f.readAll();
        };
        WebBmc bmc;
        bmc.cert = QSslCertificate(load("leaf.pem"));
        bmc.key = QSslKey(load("leaf.key"), QSsl::Rsa);
        QVERIFY(bmc.listen(QHostAddress::LocalHost));
        QVariantMap options{
            {"host", "localhost"},
            {"port", bmc.serverPort()},
            {"user", "admin"},
            {"password", "password"},
            {"autoArm", false},
            {"tls", true},
            {"allowUntrusted", false}};
        Session session;
        QSignalSpy prompt(&session, &Session::consoleCertificateUntrusted);
        session.open(options);
        QTRY_COMPARE(prompt.size(), 1);
        QVERIFY(!session.busy());
        const QVariantMap pin{
            {"host", "localhost"},
            {"port", bmc.serverPort()},
            {"sha256",
             QString::fromLatin1(
                 bmc.cert.digest(QCryptographicHash::Sha256).toHex())}};
        options["consoleTrust"] = pin;
        session.open(options);
        QTRY_COMPARE(session.status(), QString("Authenticating console…"));
        QCOMPARE(prompt.size(), 1);
        session.close();
        // Pin mismatch must reject even a normally trusted certificate and the
        // broad compatibility setting.
        const auto original = QSslConfiguration::defaultConfiguration();

        struct Restore
        {
            QSslConfiguration config;

            ~Restore()
            {
                QSslConfiguration::setDefaultConfiguration(config);
            }
        } restore{original};

        auto config = original;
        config.setCaCertificates({QSslCertificate(load("root.pem"))});
        QSslConfiguration::setDefaultConfiguration(config);
        bmc.chain = {bmc.cert, QSslCertificate(load("issuer.pem"))};
        auto wrong = pin;
        wrong["sha256"] = QString(64, '0');
        options["consoleTrust"] = wrong;
        options["allowUntrusted"] = true;
        session.open(options);
        QTRY_VERIFY(!session.busy());
        QVERIFY(session.status().contains("changed"));
        QCOMPARE(prompt.size(), 1);
        options["consoleTrust"] = pin;
        options["tls"] = false;
        session.open(options);
        QTRY_VERIFY(!session.busy());
        QVERIFY(session.status().contains("changed"));
        QTemporaryDir dir;
        Profiles profiles(dir.filePath("profiles.json"));
        options["consoleTrust"] = pin;
        QVERIFY(profiles.save("BMC", options));
        Profiles reloaded(dir.filePath("profiles.json"));
        QCOMPARE(
            reloaded.entries().first().toMap().value("consoleTrust").toMap(),
            pin);
    }

    void mediaCertificatePinning()
    {
        Session resources;
        auto load = [](const char* name)
        {
            QFile file(QString(":/tls/tests/certificates/") + name);
            file.open(QIODevice::ReadOnly);
            return file.readAll();
        };
        WebBmc bmc;
        bmc.cert = QSslCertificate(load("leaf.pem"));
        bmc.key = QSslKey(load("leaf.key"), QSsl::Rsa);
        QVERIFY(bmc.listen(QHostAddress::LocalHost));
        Launch endpoint;
        endpoint.host = "127.0.0.1";   // Deliberate hostname mismatch.
        endpoint.mediaPort = bmc.serverPort();
        endpoint.tls = true;
        Media media;
        media.probe(endpoint, false);
        QTRY_VERIFY(!media.busy());
        QCOMPARE(bmc.mediaRequests, 0);
        media.probe(endpoint, false, bmc.cert);
        QTRY_COMPARE(bmc.mediaRequests, 1);
        QVERIFY(media.busy());
        media.unmount();
        // An explicit pin wins over the broad compatibility option.
        media.probe(endpoint, true, QSslCertificate(load("root.pem")));
        QTRY_VERIFY(!media.busy());
        QVERIFY(media.status().contains("differs"));
        QCOMPARE(bmc.mediaRequests, 1);
        endpoint.tls = false;
        media.probe(endpoint, true, bmc.cert);
        QTRY_VERIFY(!media.busy());
        QVERIFY(media.status().contains("differs"));
        QCOMPARE(bmc.mediaRequests, 1);
    }

    void httpsMissingIntermediate()
    {
        auto load = [](const char* name)
        {
            QFile f(QString(":/tls/tests/certificates/") + name);
            f.open(QIODevice::ReadOnly);
            return f.readAll();
        };
        const auto original = QSslConfiguration::defaultConfiguration();

        struct Restore
        {
            QSslConfiguration config;

            ~Restore()
            {
                QSslConfiguration::setDefaultConfiguration(config);
            }
        } restore{original};

        auto config = original;
        config.setCaCertificates({QSslCertificate(load("root.pem"))});
        QSslConfiguration::setDefaultConfiguration(config);
        WebBmc bmc;
        bmc.cert = QSslCertificate(load("leaf.pem"));
        bmc.key = QSslKey(load("leaf.key"), QSsl::Rsa);
        QVERIFY(bmc.listen(QHostAddress::LocalHost));
        QTcpServer aia;
        QVERIFY(aia.listen(QHostAddress::LocalHost, 18081));
        int downloads = 0;
        const auto der = QSslCertificate(load("issuer.pem")).toDer();
        connect(
            &aia,
            &QTcpServer::newConnection,
            this,
            [&]
            {
                auto* s = aia.nextPendingConnection();
                connect(
                    s,
                    &QTcpSocket::readyRead,
                    s,
                    [&, s]
                    {
                        s->readAll();
                        ++downloads;
                        s->write(
                            "HTTP/1.1 200 OK\r\nContent-Length: " +
                            QByteArray::number(der.size()) +
                            "\r\nConnection: close\r\n\r\n" + der);
                        s->disconnectFromHost();
                    });
                connect(s, &QTcpSocket::disconnected, s, &QObject::deleteLater);
            });
        QVariantMap options{
            {"host", "localhost"},
            {"webPort", bmc.serverPort()},
            {"user", "admin"},
            {"password", "password"},
            {"allowUntrusted", false},
            {"autoReconnect", false}};
        Session session;
        session.open(options);
        QTRY_COMPARE(bmc.logins, 1);
        QCOMPARE(downloads, 1);
        QTRY_COMPARE(bmc.logouts, 1);
        session.close();
        // Cached intermediates must never act as trusted roots.
        config.setCaCertificates({});
        QSslConfiguration::setDefaultConfiguration(config);
        Session untrusted;
        untrusted.open(options);
        QTRY_VERIFY(!untrusted.busy());
        QCOMPARE(bmc.logins, 1);
        QVERIFY(untrusted.status().contains("certificate validation failed"));
    }

    void videoTraceReplay()
    {
        QTemporaryDir dir;
        VideoTrace trace;
        const auto path = dir.filePath("video.jsonl");
        QVERIFY(trace.start(path));
        Decoder decoder;
        decoder.resize({8, 8});
        const auto white = QByteArray::fromHex("000001bc0000205300000000");
        QVERIFY(decoder.decode(white, 0x57));
        QVERIFY(trace.record(
            {{"type", "request"}, {"full", true}, {"sequence", 1}}));
        QJsonObject video = {
            {"type", "video"},
            {"width", 8},
            {"height", 8},
            {"encoding", 87},
            {"payload", QString::fromLatin1(white.toBase64())},
            {"imageSha256", QString::fromLatin1(imageHash(decoder.image()))}};
        QVERIFY(trace.record(video));
        // A reconnect resets decoder state; a final disconnect must preserve
        // the last output.
        QVERIFY(trace.record({{"type", "reset"}}));
        QVERIFY(trace.record(video));
        QVERIFY(trace.record({{"type", "reset"}}));
        trace.stop();
        const auto png = dir.filePath("last.png");
        QVERIFY(replayVideoTrace(path, png).contains(
            "packets=2 compared=2 mismatches=0"));
        QCOMPARE(QImage(png).pixel(0, 0), qRgb(255, 255, 255));
        QVERIFY_EXCEPTION_THROWN(replayVideoTrace(path, png), Error);
        QVERIFY(!trace.start(path));   // Never overwrite a recording.
        const auto bad = dir.filePath("bad.jsonl");
        QVERIFY(trace.start(bad));
        video["imageSha256"] = "wrong";
        QVERIFY(trace.record(video));
        trace.stop();
        QVERIFY(replayVideoTrace(bad).contains("mismatches=1"));
        QFile damaged(bad);
        QVERIFY(damaged.open(QIODevice::Append));
        damaged.write("{");
        damaged.close();
        QVERIFY_EXCEPTION_THROWN(replayVideoTrace(bad), Error);
    }

    void bundledClientIdentity()
    {
        Session session;   // Initializes the static certificate resource.
        QSslSocket socket;
        configureClientTls(&socket);
        QVERIFY(!socket.localCertificate().isNull());
        QVERIFY(!socket.privateKey().isNull());
        QCOMPARE(socket.protocol(), QSsl::TlsV1_2);
        // On OpenSSL, compare the portable PEM identity to the original PFX.
        if (QSslSocket::activeBackend() == "openssl") {
            QFile pfx(":/resources/client.pfx");
            QVERIFY(pfx.open(QIODevice::ReadOnly));
            QSslKey key;
            QSslCertificate cert;
            QVERIFY(QSslCertificate::importPkcs12(&pfx, &key, &cert));
            QVERIFY(socket.localCertificate().toDer() == cert.toDer());
            QVERIFY(socket.privateKey().toDer() == key.toDer());
        }
    }

    void profilesPersistCredentials()
    {
        QTemporaryDir dir;
        QVERIFY(dir.isValid());
        const auto path = dir.filePath("profiles.json");
        Profiles p(path);
        QVERIFY(p.save(
            "Office",
            {{"host", "bmc"},
             {"user", "admin"},
             {"password", "SECRET"},
             {"unexpected", "SECRET"}}));
        Profiles loaded(path);
        QCOMPARE(loaded.entries().size(), 1);
        QCOMPARE(
            loaded.entries()[0].toMap().value("user").toString(),
            QString("admin"));
        QFile f(path);
        QVERIFY(f.open(QIODevice::ReadOnly));
        const auto stored = f.readAll();
#ifdef Q_OS_WIN
        QVERIFY(!stored.contains("SECRET"));
        QVERIFY(stored.contains("protectedPassword"));
#else
        QVERIFY(stored.contains("SECRET"));
#endif
        QCOMPARE(
            loaded.entries()[0].toMap().value("password").toString(),
            QString("SECRET"));
        f.close();
        QVERIFY(p.save(
            "Office",
            {{"host", "bmc2"},
             {"autoArm", false},
             {"user", "TOKEN"},
             {"password", "SECRET"}}));
        Profiles manual(path);
        QCOMPARE(manual.entries().size(), 1);
        QCOMPARE(
            manual.entries()[0].toMap().value("user").toString(),
            QString("TOKEN"));
        QCOMPARE(
            manual.entries()[0].toMap().value("password").toString(),
            QString("SECRET"));
        QVERIFY(manual.remove("Office"));
        Profiles empty(path);
        QVERIFY(empty.entries().isEmpty());
        QVERIFY(f.open(QIODevice::WriteOnly));
        f.write("broken");
        f.close();
        Profiles broken(path);
        QVERIFY(!broken.error().isEmpty());
        QVERIFY(!broken.save("New", {{"host", "bmc"}}));
        QVERIFY(f.open(QIODevice::ReadOnly));
        QCOMPARE(f.readAll(), QByteArray("broken"));
    }

    void debugLogOptInAndRotation()
    {
        QTemporaryDir dir;
        const auto path = dir.filePath("debug.log");
        DebugLog log(path);
        log.write("disabled");
        QVERIFY(!QFile::exists(path));
        log.setEnabled(true);
        log.write("connection failed");
        QFile f(path);
        QVERIFY(f.open(QIODevice::ReadOnly));
        QVERIFY(f.readAll().contains("connection failed"));
        f.close();
        log.setEnabled(false);
        QVERIFY(f.open(QIODevice::WriteOnly | QIODevice::Append));
        QVERIFY(f.resize(DebugLog::MaxFileBytes));
        f.close();
        log.setEnabled(true);
        QVERIFY(QFile::exists(path + ".old"));
        QVERIFY(QFileInfo(path).size() < 1024);
        log.clear();
        QVERIFY(log.text().isEmpty());
        QVERIFY(!QFile::exists(path));
    }

    void wireVectors()
    {
        QCOMPARE(
            keyEvent(0x41beef, true).toHex(),
            QByteArray("04000100000041beef000000000000000000"));
        QCOMPARE(
            pointerEvent(0x1234, 0x5678, 2).toHex(),
            QByteArray("050002123456780000000000000000000000"));
        QCOMPARE(
            updateRequest({640, 480}, true).toHex(),
            QByteArray("030100000000028001e0"));
        auto c = credentials("user", "pass");
        QCOMPARE(c.size(), 48);
        QCOMPARE(c.first(4), QByteArray("user"));
        QCOMPARE(c.mid(24, 4), QByteArray("pass"));
        QVERIFY_EXCEPTION_THROWN(credentials(QString(25, 'x'), "p"), Error);
        QVERIFY_EXCEPTION_THROWN(be32(QByteArray(3, 0), 0), Error);
    }

    void jnlp()
    {
        const QList<QByteArray> xmls = {
            // < 1.69.38
            QByteArray(
                "<jnlp><application-desc>"
                "<resources>"
                "<jar href=\"iKVM__V1.69.30.0x0.jar\" />"
                "</resources>"
                "<argument>example.test</argument>"
                "<argument>u&amp;x</argument>"
                "<argument>p</argument>"
                "<argument>host</argument>"
                "<argument>63630</argument>"
                "<argument>623</argument>"
                "<argument>1</argument>"
                "<argument>1</argument>"
                "<argument>1</argument>"
                "<argument>5900</argument>"
                "</application-desc></jnlp>"
            ),
            // >=1.69.38, < 1.69.40
            QByteArray(
                "<jnlp><application-desc>"
                "<resources>"
                "<jar href=\"iKVM__V1.69.38.0x0.jar\" />"
                "</resources>"
                "<argument>example.test</argument>"
                "<argument>u&amp;x</argument>"
                "<argument>p</argument>"
                "<argument>host</argument>"
                "<argument>63630</argument>"
                "<argument>63631</argument>"
                "<argument>0</argument>"
                "<argument>0</argument>"
                "<argument>1</argument>"
                "<argument>5900</argument>"
                "<argument>623</argument>"
                "</application-desc></jnlp>"
            ),
        };

        for (auto const &xml : xmls) {
            auto l = parseJnlp(xml);
            QCOMPARE(l.port, 5900);
            QVERIFY(l.tls);
            QCOMPARE(l.user, QString("u&x"));
            auto plain = xml;
            plain.replace(
                "<argument>1</argument><argument>5900",
                "<argument>0</argument><argument>5900");
            l = parseJnlp(plain);
            QCOMPARE(l.port, 63630);
            QVERIFY(!l.tls);
            QVERIFY_EXCEPTION_THROWN(parseJnlp("<html>login failed</html>"), Error);
            QVERIFY_EXCEPTION_THROWN(parseJnlp("<!DOCTYPE jnlp><jnlp/>"), Error);
        }
    }

    void hermonFramesAndClipping()
    {
        Decoder d;
        d.resize({17, 17});
        QVERIFY(d.decode(hermon(17, 17, 0x7c00), 0));
        QCOMPARE(d.image().pixel(0, 0), qRgb(248, 0, 0));
        QByteArray tile(528, 0);
        put32(tile, 2, 1);
        tile[14] = 1;
        tile[15] = 1;
        for (int p = 16; p < 528; p += 2) {
            qToLittleEndian<quint16>(0x03e0, tile.data() + p);
        }
        QVERIFY(d.decode(tile, 0));
        QCOMPARE(d.image().pixel(16, 16), qRgb(0, 248, 0));
        QCOMPARE(d.image().pixel(15, 16), qRgb(248, 0, 0));
        tile.chop(1);
        QVERIFY_EXCEPTION_THROWN(d.decode(tile, 0), Error);
        QVERIFY_EXCEPTION_THROWN(d.resize({65535, 65535}), Error);
    }

    void aspeedVqAndSessionIsolation()
    {
        Decoder first, second;
        first.resize({8, 8});
        second.resize({8, 8});
        // 1-colour VQ using cache entry 1 (white), followed by frame-end. Bits
        // are LE words.
        QByteArray white = QByteArray::fromHex("000001bc0000205300000000");
        QVERIFY(first.decode(white, 0x57));
        QCOMPARE(first.image().pixel(0, 0), qRgb(255, 255, 255));
        // Cache entry 0 is black. Ensure another context cannot overwrite the
        // first image.
        QByteArray black = QByteArray::fromHex("000001bc0000205100000000");
        QVERIFY(second.decode(black, 0x57));
        QCOMPARE(second.image().pixel(0, 0), qRgb(0, 0, 0));
        QCOMPARE(first.image().pixel(0, 0), qRgb(255, 255, 255));
        auto snapshot = first.image();
        QVERIFY(first.decode(black, 0x57));
        QCOMPARE(snapshot.pixel(0, 0), qRgb(255, 255, 255));
        auto end = QByteArray::fromHex("000001bc0000009000000000");
        QVERIFY(!first.decode(end, 0x57));
        auto bad = white;
        bad[0] = 12;
        QVERIFY_EXCEPTION_THROWN(first.decode(bad, 0x57), Error);
    }

    void concurrentSessionsRecoverStalledVideo()
    {
        QTcpServer server;
        QVERIFY(server.listen(QHostAddress::LocalHost));
        Session first, second;
        for (auto* session: {&first, &second}) {
            session->setStreaming(true, 0, 1);
            session->open(
                {{"host", "127.0.0.1"},
                 {"user", "u"},
                 {"password", "p"},
                 {"autoArm", false},
                 {"tls", false},
                 {"port", server.serverPort()}});
            QTRY_VERIFY(server.hasPendingConnections());
            auto* peer = server.nextPendingConnection();
            peer->write("RFB 003.008\n");
            QTRY_VERIFY(peer->bytesAvailable() >= 12);
            peer->readAll();
            peer->write(QByteArray::fromHex("0110"));
            QTRY_VERIFY(peer->bytesAvailable() >= 1);
            peer->readAll();
            peer->write(QByteArray(24, 0));
            QTRY_VERIFY(peer->bytesAvailable() >= 48);
            peer->readAll();
            peer->write(QByteArray(4, 0));
            QTRY_VERIFY(peer->bytesAvailable() >= 1);
            peer->readAll();
            QByteArray init(36, 0);
            put16(init, 0, 2);
            put16(init, 2, 2);
            peer->write(init);
            QTRY_VERIFY(session->connected());
            QTRY_VERIFY(peer->bytesAvailable() >= 22);
            peer->readAll();
            QSignalSpy frames(session, &Session::frameReady);
            peer->write(frameMessage(hermon(2, 2, 0x1f), 2, 2));
            QTRY_COMPARE(frames.size(), 1);
            QTRY_VERIFY(peer->bytesAvailable() >= 10);
            QVERIFY(peer->readAll().contains(updateRequest({2, 2}, true)));
            // Withhold the incremental reply but keep sending valid power
            // replies.
            QTimer replies;
            replies.setInterval(100);
            connect(
                &replies,
                &QTimer::timeout,
                peer,
                [peer] { peer->write(QByteArray::fromHex("37000000")); });
            replies.start();
            QByteArray requests;
            const auto receivedFullRequest = [&]
            {
                requests += peer->readAll();
                return requests.contains(updateRequest({2, 2}, false));
            };
            QTRY_VERIFY_WITH_TIMEOUT(receivedFullRequest(), 5000);
            peer->write(frameMessage(hermon(2, 2, 0x7c00), 2, 2));
            QTRY_COMPARE(frames.size(), 2);
            QCOMPARE(
                qvariant_cast<QImage>(frames.last()[0]).pixel(0, 0),
                qRgb(248, 0, 0));
            session->setStreaming(true, 0, 0);
            QTRY_VERIFY(peer->bytesAvailable() >= 10);
            peer->readAll();
            session->setDuplicateEndpoint(true);
            QTRY_VERIFY(peer->bytesAvailable() >= 10);
            QVERIFY(peer->readAll().contains(updateRequest({2, 2}, false)));
            peer->write(frameMessage(hermon(2, 2, 0x1f), 2, 2));
            QTRY_COMPARE(frames.size(), 3);
            QTRY_VERIFY(peer->bytesAvailable() >= 10);
            QVERIFY(peer->readAll().contains(updateRequest({2, 2}, false)));
            session->setDuplicateEndpoint(false);
            QTRY_VERIFY(peer->bytesAvailable() >= 10);
            peer->readAll();   // One resync full frame.
            peer->write(frameMessage(hermon(2, 2, 0x7c00), 2, 2));
            QTRY_COMPARE(frames.size(), 4);
            QTRY_VERIFY(peer->bytesAvailable() >= 10);
            QVERIFY(peer->readAll().contains(updateRequest({2, 2}, true)));
        }
        QVERIFY(first.connected());
        QVERIFY(second.connected());
    }

    void fragmentedSession()
    {
        QTcpServer server;
        QVERIFY(server.listen(QHostAddress::LocalHost));
        Session s;
        QSignalSpy frames(&s, &Session::frameReady);
        s.open(
            {{"host", "127.0.0.1"},
             {"user", "u"},
             {"password", "p"},
             {"autoArm", false},
             {"tls", false},
             {"port", server.serverPort()}});
        QTRY_VERIFY(server.hasPendingConnections());
        auto* peer = server.nextPendingConnection();
        peer->write("RFB 003.");
        QTest::qWait(5);
        QCOMPARE(peer->bytesAvailable(), 0);
        peer->write("008\n");
        QTRY_VERIFY(peer->bytesAvailable() >= 12);
        QCOMPARE(peer->read(12), QByteArray("RFB 003.008\n"));
        peer->write(QByteArray::fromHex("0110"));
        QTRY_VERIFY(peer->bytesAvailable() >= 1);
        QCOMPARE(peer->read(1), QByteArray(1, 16));
        peer->write(QByteArray(23, 0));
        QTest::qWait(5);
        QCOMPARE(peer->bytesAvailable(), 0);
        peer->write(QByteArray(1, 0));
        QTRY_VERIFY(peer->bytesAvailable() >= 48);
        QCOMPARE(peer->read(48), credentials("u", "p"));
        peer->write(QByteArray(4, 0));
        QTRY_VERIFY(peer->bytesAvailable() >= 1);
        QCOMPARE(peer->read(1), QByteArray(1, 0));
        QByteArray init(36, 0);
        put16(init, 0, 2);
        put16(init, 2, 2);
        peer->write(init.first(35));
        QTest::qWait(5);
        QVERIFY(!s.connected());
        peer->write(init.last(1));
        QTRY_VERIFY(s.connected());
        QTRY_VERIFY(peer->bytesAvailable() >= 22);
        peer->readAll();
        const auto update = frameMessage(hermon(2, 2, 0x1f), 2, 2);
        peer->write(update.first(update.size() - 1));
        QTest::qWait(5);
        QCOMPARE(frames.size(), 0);
        peer->write(update.last(1));
        QTRY_COMPARE(frames.size(), 1);
        QCOMPARE(
            qvariant_cast<QImage>(frames[0][0]).pixel(0, 0),
            qRgb(0, 0, 248));
        s.key(0xe0, true);
        s.releaseInput();
        QTRY_VERIFY(peer->bytesAvailable() >= 36);
        const auto tx = peer->readAll();
        QVERIFY(tx.contains(keyEvent(0xe0, true) + keyEvent(0xe0, false)));
        QByteArray deny(265, 0);
        deny[0] = 0x39;
        put32(deny, 1, 1);
        put32(deny, 5, 4);
        peer->write(deny);
        QTRY_VERIFY(s.status().contains("view only"));
        peer->readAll();
        s.key(4, true);
        QTest::qWait(5);
        QVERIFY(!peer->readAll().contains(keyEvent(4, true)));
        // Reject a hostile payload length before allocating or waiting for its
        // body.
        QByteArray huge(24, 0);
        put16(huge, 2, 1);
        put32(huge, 20, 0xffffffff);
        peer->write(huge);
        QTRY_VERIFY(!s.busy());
        QVERIFY(s.status().contains("too large"));
    }

    void reconnectFreshTokensAndCancel()
    {
        Session s;   // Initializes the bundled certificate resource.
        WebBmc web;
        QFile pfx(":/resources/client.pfx");
        QVERIFY(pfx.open(QIODevice::ReadOnly));
        QVERIFY(QSslCertificate::importPkcs12(&pfx, &web.key, &web.cert));
        QVERIFY(web.listen(QHostAddress::LocalHost));
        QTcpServer console;
        QVERIFY(console.listen(QHostAddress::LocalHost));
        web.consolePort = console.serverPort();
        auto options = QVariantMap{
            {"host", "127.0.0.1"},
            {"user", "admin"},
            {"password", "password"},
            {"webPort", web.serverPort()},
            {"allowUntrusted", true}};
        auto handshake = [&](QTcpSocket* peer, int login)
        {
            peer->write("RFB 003.008\n");
            QTRY_VERIFY(peer->bytesAvailable() >= 12);
            peer->readAll();
            peer->write(QByteArray::fromHex("0110") + QByteArray(24, 0));
            QTRY_VERIFY(peer->bytesAvailable() >= 49);
            QCOMPARE(
                peer->readAll().mid(1),
                credentials("token" + QString::number(login), "pass"));
            QByteArray init(36, 0);
            put16(init, 0, 2);
            put16(init, 2, 2);
            peer->write(QByteArray(4, 0) + init);
            QTRY_VERIFY(s.connected());
        };
        auto untrustedOptions = options;
        untrustedOptions["allowUntrusted"] = false;
        s.open(untrustedOptions);
        QTRY_VERIFY(!s.busy());
        QVERIFY(s.status().contains("HTTPS certificate validation failed"));
        QCOMPARE(web.logins, 0);
        s.open(options);
        QTRY_VERIFY(console.hasPendingConnections());
        auto* peer = console.nextPendingConnection();
        handshake(peer, 1);
        s.setKeepMedia(true);
        peer->abort();
        QTRY_VERIFY(s.status().contains("reconnect 1/30"));
        QTRY_VERIFY_WITH_TIMEOUT(console.hasPendingConnections(), 7000);
        peer = console.nextPendingConnection();
        handshake(peer, 2);
        QCOMPARE(web.logins, 2);
        QCOMPARE(
            web.logouts,
            0);   // A mounted ISO keeps the previous web login alive.
        s.setKeepMedia(false);
        QTRY_COMPARE(web.logouts, 1);
        peer->abort();
        QTRY_VERIFY(s.status().contains("reconnect 2/30"));
        s.close();
        QTest::qWait(5200);
        QCOMPARE(web.logins, 2);
        QCOMPARE(s.status(), QString("Disconnected"));
        // A new session that loses its transport must stop if web
        // authentication is rejected.
        s.open(options);
        QTRY_VERIFY(console.hasPendingConnections());
        peer = console.nextPendingConnection();
        handshake(peer, 3);
        web.reject = true;
        peer->abort();
        QTRY_VERIFY_WITH_TIMEOUT(!s.busy(), 7000);
        QVERIFY(s.status().contains("check credentials"));
        const int attempts = web.logins;
        QTest::qWait(2200);
        QCOMPARE(web.logins, attempts);
    }

    void paletteAndPlaneFrames()
    {
        Decoder d;
        d.resize({8, 1});
        QByteArray palette(1034 + 8, 0);
        palette[0] = 1;
        palette[1] = 1;
        put32(palette, 6, palette.size());
        for (int i = 0; i < 256; ++i) {
            palette[10 + 4 * i] = char(i);
            palette[11 + 4 * i] = char(i * 2);
            palette[12 + 4 * i] = char(i * 3);
        }
        for (int i = 0; i < 8; ++i) {
            palette[1034 + i] = char(i);
        }
        QVERIFY(d.decode(palette, 0));
        QCOMPARE(d.image().pixel(7, 0), qRgb(21, 14, 7));
        auto packet = [](int type, const QByteArray& planes, bool full)
        {
            QByteArray body(4, 0);
            qToLittleEndian<quint32>(planes.size(), body.data());
            body += planes;
            if (!full) {
                body = QByteArray::fromHex("0100000008010000") + body;
            }
            QByteArray p(10, 0);
            p[0] = full ? 1 : 0;
            p[1] = char(type);
            p += body;
            put32(p, 6, p.size());
            return p;
        };
        QByteArray planes(32, 0);
        planes[15] = 4;
        planes[0] = 1;
        planes[24] = 1;
        QVERIFY(d.decode(packet(4, planes, true), 0));
        QCOMPARE(d.image().pixel(0, 0), qRgb(128, 128, 0));
        QCOMPARE(d.image().pixel(2, 0), qRgb(0, 0, 1));
        QVERIFY(d.decode(packet(4, planes, false), 0));
        QCOMPARE(d.image().pixel(2, 0), qRgb(0, 0, 1));
        planes = QByteArray(16, 0);
        planes[0] = 1;
        planes[15] = 1;
        QVERIFY(d.decode(packet(2, planes, true), 0));
        QCOMPARE(d.image().pixel(0, 0), qRgb(128, 0, 8));
        auto bad = packet(2, planes, true);
        bad[10] = char(0xff);
        QVERIFY_EXCEPTION_THROWN(d.decode(bad, 0), Error);
        bad = packet(4, QByteArray::fromHex("55ff00"), true);
        QVERIFY_EXCEPTION_THROWN(d.decode(bad, 0), Error);
    }

    void mediaProtocolAndScsi()
    {
        QCOMPARE(mediaControl(8).toHex(), QByteArray("0000000800000000"));
        const auto attach = mediaAttach("user", "pass", 0x12345678);
        QCOMPARE(attach.size(), 246);
        QCOMPARE(attach.mid(44, 4).toHex(), QByteArray("78563412"));
        QCOMPARE(
            attach.mid(226),
            QMessageAuthenticationCode::hash(
                attach.first(226),
                "userpass",
                QCryptographicHash::Sha1));
        QCOMPARE(attach.mid(52, 8).toHex(), QByteArray("1212010002000000"));
        QVERIFY_EXCEPTION_THROWN(mediaAttach(QString(16, 'x'), "p", 0), Error);
        QTemporaryDir dir;
        QFile iso(dir.filePath("test.iso"));
        QVERIFY(iso.open(QIODevice::WriteOnly));
        iso.write(QByteArray(2049, 'X'));
        iso.close();
        CdRom cd(iso.fileName());
        QCOMPARE(cd.blocks(), quint64(2));
        QByteArray cdb(16, 0);
        cdb[0] = 0x12;
        auto reply = cd.execute(cdb, 36);
        QCOMPARE(reply.status, quint8(0));
        QCOMPARE(reply.data.mid(8), QByteArray("IPMI    Virtual CDROM   3000"));
        cdb[0] = 0x25;
        QCOMPARE(
            cd.execute(cdb, 8).data.toHex(),
            QByteArray("0000000100000800"));
        cdb[0] = 0x28;
        put32(cdb, 2, 1);
        put16(cdb, 7, 1);
        reply = cd.execute(cdb, 2048);
        QCOMPARE(reply.data.size(), 2048);
        QCOMPARE(reply.data[0], 'X');
        QCOMPARE(reply.data.mid(1), QByteArray(2047, 0));
        put32(cdb, 2, 2);
        QCOMPARE(cd.execute(cdb, 2048).status, quint8(1));
        cdb.fill(0);
        cdb[0] = 3;
        reply = cd.execute(cdb, 18);
        QCOMPARE(quint8(reply.data[2]), 5);
        QCOMPARE(quint8(reply.data[12]), 0x21);
        QCOMPARE(quint8(cd.execute(cdb, 18).data[2]), 0);
        cdb.fill(0);
        cdb[0] = 0x43;
        reply = cd.execute(cdb, 20);
        QCOMPARE(
            reply.data.toHex(),
            QByteArray("0012010100140100000000000014aa0000000002"));
        cdb[6] = char(0xaa);
        cdb[1] = 2;
        QCOMPARE(
            cd.execute(cdb, 12).data.toHex(),
            QByteArray("000a01010014aa0000000202"));
        cdb[6] = 3;
        QCOMPARE(cd.execute(cdb, 12).status, quint8(1));
        cdb.fill(0);
        cdb[0] = 0x5a;
        cdb[2] = 0x2a;
        QCOMPARE(cd.execute(cdb, 64).data.size(), 38);
        cdb[0] = 0x12;
        QCOMPARE(cd.execute(cdb, 0).data.size(), 0);
        QCOMPARE(cd.execute(cdb, 0xffffffff).status, quint8(1));
        cdb[0] = 0x2a;
        QCOMPARE(
            cd.execute(cdb, 2048).status,
            quint8(1));   // Never write to the ISO.
    }

    void mediaHandshakeReadAndDetach()
    {
        QTemporaryDir dir;
        QFile iso(dir.filePath("test.iso"));
        QVERIFY(iso.open(QIODevice::WriteOnly));
        iso.write(QByteArray(2048, 'Z'));
        iso.close();
        QTcpServer server;
        QVERIFY(server.listen(QHostAddress::LocalHost));
        Launch l;
        l.host = "127.0.0.1";
        l.user = "u";
        l.password = "p";
        l.tls = false;
        l.mediaPort = server.serverPort();
        Media m;
        m.mount(l, false, iso.fileName());
        QTRY_VERIFY(server.hasPendingConnections());
        auto* health = server.nextPendingConnection();
        QTRY_VERIFY(health->bytesAvailable() >= 8);
        QCOMPARE(health->readAll(), mediaControl(8));
        health->write(mediaControl(9, QByteArray::fromHex("03ffffff")));
        QTRY_VERIFY(server.hasPendingConnections());
        auto* init = server.nextPendingConnection();
        QTRY_VERIFY(init->bytesAvailable() >= 8);
        QCOMPARE(init->readAll(), mediaControl(10));
        init->write(mediaControl(11));
        QTRY_VERIFY(server.hasPendingConnections());
        auto* data = server.nextPendingConnection();
        QTRY_VERIFY(server.hasPendingConnections());
        health = server.nextPendingConnection();
        QTRY_VERIFY(health->bytesAvailable() >= 8);
        QCOMPARE(health->readAll(), mediaControl(8));
        health->write(mediaControl(9, QByteArray::fromHex("03ffffff")));
        QTRY_VERIFY(data->bytesAvailable() >= 246);
        QCOMPARE(data->read(246).size(), 246);
        auto accepted = mediaControl(2, QByteArray(1, 0));
        data->write(accepted.first(7));
        QTest::qWait(5);
        QVERIFY(!m.status().startsWith("Mounted:"));
        data->write(accepted.mid(7));
        QTRY_VERIFY(m.status().startsWith("Mounted:"));
        QTRY_VERIFY(data->bytesAvailable() >= 16);
        QCOMPARE(
            data->readAll(),
            mediaControl(7, QByteArray::fromHex("0503011002200330")));
        QByteArray command(39, 0);
        command[0] = 0x11;
        command[2] = 2;
        qToLittleEndian<quint32>(31, command.data() + 4);
        command.replace(8, 4, "USBC");
        qToLittleEndian<quint32>(0x1234, command.data() + 12);
        qToLittleEndian<quint32>(2048, command.data() + 16);
        command[20] = char(0x80);
        command[22] = 10;
        command[23] = 0x28;
        command[31] = 1;
        data->write(command);
        QTRY_VERIFY(data->bytesAvailable() >= 2077);
        auto response = data->readAll();
        QCOMPARE(response.mid(8, 2048), QByteArray(2048, 'Z'));
        QCOMPARE(response.mid(2064, 4), QByteArray("USBS"));
        QCOMPARE(quint8(response.last(1)[0]), 0);
        // The media channel does not depend on a video Session lifetime.
        {
            Session video;
            video.close();
        }
        QVERIFY(m.busy());
        m.unmount();
        QTRY_VERIFY(data->bytesAvailable() >= 8);
        QCOMPARE(data->readAll(), mediaControl(5));
        data->write(mediaControl(6));
        QTRY_VERIFY(!m.busy());
        m.mount(l, false, iso.fileName());
        QTRY_VERIFY(server.hasPendingConnections());
        health = server.nextPendingConnection();
        QTRY_VERIFY(health->bytesAvailable() >= 8);
        health->readAll();
        health->write(mediaControl(9, QByteArray::fromHex("03ff01ff")));
        QTRY_VERIFY(!m.busy());
        QVERIFY(m.status().contains("occupied"));
    }

    void cancelConnection()
    {
        QTcpServer server;
        QVERIFY(server.listen(QHostAddress::LocalHost));
        Session s;
        s.open(
            {{"host", "127.0.0.1"},
             {"user", "u"},
             {"password", "p"},
             {"autoArm", false},
             {"tls", false},
             {"port", server.serverPort()}});
        QTRY_VERIFY(server.hasPendingConnections());
        s.close();
        QVERIFY(!s.busy());
        QTest::qWait(10);
        QCOMPARE(s.status(), QString("Disconnected"));
    }
};
QTEST_GUILESS_MAIN(CoreTests)
#include "core_tests.moc"
