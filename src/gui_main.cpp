/**
 * @file gui_main.cpp
 * @brief Optional native Qt interface for the KernelVault C++ engine.
 */

#include "KeyDerivation.hpp"
#include "VaultManager.hpp"

#include <QApplication>
#include <QComboBox>
#include <QDir>
#include <QFileDialog>
#include <QFileInfo>
#include <QFormLayout>
#include <QFrame>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMainWindow>
#include <QMessageBox>
#include <QMetaObject>
#include <QPushButton>
#include <QTabWidget>
#include <QThread>
#include <QVBoxLayout>
#include <QWidget>

#include <exception>
#include <filesystem>
#include <functional>
#include <string>
#include <utility>

namespace {

std::filesystem::path toPath(const QString& value) {
    const QByteArray utf8 = value.toUtf8();
    return std::filesystem::path(std::string(utf8.constData(),
                                             static_cast<size_t>(utf8.size())));
}

class MainWindow final : public QMainWindow {
public:
    MainWindow() {
        setWindowTitle("KernelVault | Guided Desktop Demo");
        setMinimumSize(820, 620);
        resize(1024, 700);

        auto* central = new QWidget(this);
        auto* root = new QVBoxLayout(central);
        root->setContentsMargins(28, 24, 28, 24);
        root->setSpacing(16);

        auto* heading = new QLabel("KernelVault", central);
        heading->setObjectName("heading");
        auto* subtitle = new QLabel(
            "A guided view of the C++ vault engine and Linux kernel-driver boundary.", central);
        subtitle->setObjectName("muted");
        subtitle->setWordWrap(true);
        root->addWidget(heading);
        root->addWidget(subtitle);

        root->addWidget(buildVaultPanel(central));
        root->addWidget(buildFlowPanel(central));
        root->addWidget(buildOperations(central), 1);

        m_resultLabel = new QLabel("Choose a vault to begin.", central);
        m_resultLabel->setObjectName("result");
        m_resultLabel->setWordWrap(true);
        root->addWidget(m_resultLabel);
        setCentralWidget(central);

        setStyleSheet(R"(
            QMainWindow, QWidget { background: #f4f7fb; color: #182230; font-size: 14px; }
            QLabel#heading { font-size: 28px; font-weight: 700; color: #14243a; }
            QLabel#muted { color: #62748a; }
            QGroupBox { background: #ffffff; border: 1px solid #d9e2ec; border-radius: 12px;
                        margin-top: 12px; padding: 14px; font-weight: 650; }
            QGroupBox::title { subcontrol-origin: margin; left: 14px; padding: 0 5px; }
            QLineEdit, QComboBox { background: #ffffff; border: 1px solid #c7d2df;
                                  border-radius: 7px; padding: 9px 10px; min-height: 20px; }
            QLineEdit:focus, QComboBox:focus { border: 2px solid #3478df; }
            QPushButton { background: #e9eff7; border: 1px solid #ced9e6; border-radius: 7px;
                          padding: 9px 14px; font-weight: 600; }
            QPushButton:hover { background: #dce8f7; }
            QPushButton:disabled { color: #8795a5; background: #edf0f4; }
            QPushButton#primary { color: white; background: #2869d8; border-color: #2869d8; }
            QPushButton#primary:hover { background: #1e58bc; }
            QTabWidget::pane { background: #ffffff; border: 1px solid #d9e2ec;
                               border-radius: 10px; top: -1px; }
            QTabBar::tab { background: #e9eff7; padding: 10px 18px; margin-right: 4px;
                           border-top-left-radius: 7px; border-top-right-radius: 7px; }
            QTabBar::tab:selected { color: #174ea6; background: #ffffff; font-weight: 700; }
            QFrame#flowStep { background: #ffffff; border: 1px solid #d9e2ec; border-radius: 9px; }
            QLabel#flowTitle { color: #1b3b66; font-weight: 700; }
            QLabel#statusReady { color: #13734a; font-weight: 700; }
            QLabel#statusWarning { color: #9a5b00; font-weight: 700; }
            QLabel#result { padding: 8px 2px; color: #31506f; }
        )");

        connect(m_vaultPath, &QLineEdit::editingFinished, this, [this] { refreshVaultState(); });
        refreshVaultState();
    }

    ~MainWindow() override {
        if (m_worker != nullptr) {
            m_worker->wait();
        }
    }

private:
    QLineEdit* m_vaultPath{};
    QLabel* m_vaultState{};
    QLabel* m_engineState{};
    QLabel* m_flowStepOneDetail{};
    QLabel* m_flowStepTwoTitle{};
    QLabel* m_flowStepTwoDetail{};
    QLabel* m_flowStepThreeTitle{};
    QLabel* m_flowStepThreeDetail{};
    QPushButton* m_initializeButton{};
    QTabWidget* m_tabs{};
    QLineEdit* m_encryptInput{};
    QLineEdit* m_encryptPassword{};
    QPushButton* m_encryptButton{};
    QComboBox* m_decryptRecord{};
    QLineEdit* m_decryptOutput{};
    QLineEdit* m_decryptPassword{};
    QPushButton* m_decryptButton{};
    QLabel* m_resultLabel{};
    QThread* m_worker{};
    bool m_vaultInitialized{false};

    QWidget* buildVaultPanel(QWidget* parent) {
        auto* group = new QGroupBox("1. Vault", parent);
        auto* layout = new QVBoxLayout(group);
        auto* pathRow = new QHBoxLayout();
        m_vaultPath = new QLineEdit(QDir::homePath() + "/kvault-demo-vault", group);
        m_vaultPath->setPlaceholderText("Vault directory");
        auto* browse = new QPushButton("Choose folder", group);
        connect(browse, &QPushButton::clicked, this, [this] {
            const QString selected = QFileDialog::getExistingDirectory(
                this, "Choose vault folder", m_vaultPath->text());
            if (!selected.isEmpty()) {
                m_vaultPath->setText(selected);
                refreshVaultState();
            }
        });
        pathRow->addWidget(m_vaultPath, 1);
        pathRow->addWidget(browse);
        layout->addLayout(pathRow);

        auto* stateRow = new QHBoxLayout();
        m_vaultState = new QLabel(group);
        m_engineState = new QLabel(group);
        m_initializeButton = new QPushButton("Initialize vault", group);
        connect(m_initializeButton, &QPushButton::clicked, this, [this] { initializeVault(); });
        stateRow->addWidget(m_vaultState, 1);
        stateRow->addWidget(m_engineState, 1);
        stateRow->addWidget(m_initializeButton);
        layout->addLayout(stateRow);
        return group;
    }

    QWidget* buildFlowPanel(QWidget* parent) {
        auto* group = new QGroupBox("What happens to your file", parent);
        auto* layout = new QHBoxLayout(group);
        auto* cardOne = new QFrame(group);
        auto* cardOneLayout = new QVBoxLayout(cardOne);
        auto* titleOne = new QLabel("01  Choose", cardOne);
        titleOne->setObjectName("flowTitle");
        m_flowStepOneDetail = new QLabel(cardOne);
        m_flowStepOneDetail->setObjectName("muted");
        m_flowStepOneDetail->setWordWrap(true);
        cardOneLayout->addWidget(titleOne);
        cardOneLayout->addWidget(m_flowStepOneDetail);
        cardOne->setObjectName("flowStep");

        auto* cardTwo = new QFrame(group);
        auto* cardTwoLayout = new QVBoxLayout(cardTwo);
        m_flowStepTwoTitle = new QLabel(cardTwo);
        m_flowStepTwoTitle->setObjectName("flowTitle");
        m_flowStepTwoDetail = new QLabel(cardTwo);
        m_flowStepTwoDetail->setObjectName("muted");
        m_flowStepTwoDetail->setWordWrap(true);
        cardTwoLayout->addWidget(m_flowStepTwoTitle);
        cardTwoLayout->addWidget(m_flowStepTwoDetail);
        cardTwo->setObjectName("flowStep");

        auto* cardThree = new QFrame(group);
        auto* cardThreeLayout = new QVBoxLayout(cardThree);
        m_flowStepThreeTitle = new QLabel(cardThree);
        m_flowStepThreeTitle->setObjectName("flowTitle");
        m_flowStepThreeDetail = new QLabel(cardThree);
        m_flowStepThreeDetail->setObjectName("muted");
        m_flowStepThreeDetail->setWordWrap(true);
        cardThreeLayout->addWidget(m_flowStepThreeTitle);
        cardThreeLayout->addWidget(m_flowStepThreeDetail);
        cardThree->setObjectName("flowStep");

        layout->addWidget(cardOne, 1);
        layout->addWidget(cardTwo, 1);
        layout->addWidget(cardThree, 1);
        return group;
    }

    QWidget* buildOperations(QWidget* parent) {
        m_tabs = new QTabWidget(parent);
        m_tabs->addTab(buildEncryptTab(m_tabs), "Encrypt a file");
        m_tabs->addTab(buildDecryptTab(m_tabs), "Decrypt a record");
        connect(m_tabs, &QTabWidget::currentChanged, this,
                [this](int) { updateFlowDescription(); });
        updateFlowDescription();
        return m_tabs;
    }

    void updateFlowDescription() {
        if (m_tabs->currentIndex() == 0) {
            m_flowStepOneDetail->setText("Select a plaintext source file.");
            m_flowStepTwoTitle->setText("02  Encrypt + authenticate");
            m_flowStepTwoDetail->setText("AES-256-CBC protects the data; HMAC-SHA256 authenticates the record.");
            m_flowStepThreeTitle->setText("03  Store protected record");
            m_flowStepThreeDetail->setText("The encrypted record is saved in the selected vault.");
        } else {
            m_flowStepOneDetail->setText("Choose a protected record from the selected vault.");
            m_flowStepTwoTitle->setText("02  Verify before decrypting");
            m_flowStepTwoDetail->setText("HMAC-SHA256 is checked before any plaintext is written.");
            m_flowStepThreeTitle->setText("03  Restore plaintext");
            m_flowStepThreeDetail->setText("After verification, decrypted bytes are atomically written to your chosen path.");
        }
    }

    QWidget* buildEncryptTab(QWidget* parent) {
        auto* page = new QWidget(parent);
        auto* layout = new QVBoxLayout(page);
        layout->setContentsMargins(20, 18, 20, 18);
        auto* form = new QFormLayout();
        auto* fileRow = new QWidget(page);
        auto* fileLayout = new QHBoxLayout(fileRow);
        fileLayout->setContentsMargins(0, 0, 0, 0);
        m_encryptInput = new QLineEdit(fileRow);
        m_encryptInput->setReadOnly(true);
        auto* chooseFile = new QPushButton("Select file…", fileRow);
        connect(chooseFile, &QPushButton::clicked, this, [this] {
            const QString selected = QFileDialog::getOpenFileName(this, "Select a file to encrypt");
            if (!selected.isEmpty()) {
                m_encryptInput->setText(selected);
            }
        });
        fileLayout->addWidget(m_encryptInput, 1);
        fileLayout->addWidget(chooseFile);
        form->addRow("Plaintext file", fileRow);

        m_encryptPassword = new QLineEdit(page);
        m_encryptPassword->setEchoMode(QLineEdit::Password);
        m_encryptPassword->setPlaceholderText("Enter demo passphrase");
        form->addRow("Master passphrase", m_encryptPassword);
        layout->addLayout(form);

        auto* note = new QLabel(
            "The encrypted record is written to the selected vault. This demo uses AES-256-CBC "
            "and authenticates the record before it can be decrypted.", page);
        note->setObjectName("muted");
        note->setWordWrap(true);
        layout->addWidget(note);
        m_encryptButton = new QPushButton("Encrypt and store", page);
        m_encryptButton->setObjectName("primary");
        connect(m_encryptButton, &QPushButton::clicked, this, [this] { encryptSelectedFile(); });
        layout->addWidget(m_encryptButton, 0, Qt::AlignLeft);
        layout->addStretch(1);
        return page;
    }

    QWidget* buildDecryptTab(QWidget* parent) {
        auto* page = new QWidget(parent);
        auto* layout = new QVBoxLayout(page);
        layout->setContentsMargins(20, 18, 20, 18);
        auto* form = new QFormLayout();
        m_decryptRecord = new QComboBox(page);
        form->addRow("Protected record", m_decryptRecord);

        auto* outputRow = new QWidget(page);
        auto* outputLayout = new QHBoxLayout(outputRow);
        outputLayout->setContentsMargins(0, 0, 0, 0);
        m_decryptOutput = new QLineEdit(outputRow);
        m_decryptOutput->setPlaceholderText("Choose where to save restored plaintext");
        auto* chooseOutput = new QPushButton("Save as…", outputRow);
        connect(chooseOutput, &QPushButton::clicked, this, [this] {
            QString suggested = QDir::homePath() + "/restored-file";
            if (m_decryptRecord->currentIndex() >= 0) {
                suggested = QDir::homePath() + "/" + m_decryptRecord->currentText() + ".restored";
            }
            const QString selected = QFileDialog::getSaveFileName(
                this, "Choose restored file destination", suggested);
            if (!selected.isEmpty()) {
                m_decryptOutput->setText(selected);
            }
        });
        outputLayout->addWidget(m_decryptOutput, 1);
        outputLayout->addWidget(chooseOutput);
        form->addRow("Restored file path", outputRow);

        m_decryptPassword = new QLineEdit(page);
        m_decryptPassword->setEchoMode(QLineEdit::Password);
        m_decryptPassword->setPlaceholderText("Enter the passphrase used for encryption");
        form->addRow("Master passphrase", m_decryptPassword);
        layout->addLayout(form);

        auto* note = new QLabel(
            "KernelVault verifies the record's HMAC before decryption. If authentication fails, "
            "no plaintext output is committed.", page);
        note->setObjectName("muted");
        note->setWordWrap(true);
        layout->addWidget(note);
        m_decryptButton = new QPushButton("Verify and restore file", page);
        m_decryptButton->setObjectName("primary");
        connect(m_decryptButton, &QPushButton::clicked, this, [this] { decryptSelectedFile(); });
        layout->addWidget(m_decryptButton, 0, Qt::AlignLeft);
        layout->addStretch(1);
        return page;
    }

    void refreshVaultState() {
        if (m_worker != nullptr || m_vaultPath == nullptr) {
            return;
        }
        try {
            kvault::VaultManager vault(toPath(m_vaultPath->text()));
            const kvault::VaultStatus status = vault.inspectStatus();
            m_vaultInitialized = status.is_initialized;
            m_vaultState->setObjectName(m_vaultInitialized ? "statusReady" : "statusWarning");
            m_vaultState->setText(m_vaultInitialized
                ? QString("Vault ready · %1 protected record(s)").arg(status.file_count)
                : "Vault not initialized");
            m_engineState->setText(status.kernel_driver_available
                ? "Driver device: available"
                : "Driver device: unavailable · C++ fallback");
            m_initializeButton->setEnabled(!m_vaultInitialized);

            m_decryptRecord->clear();
            for (const std::string& name : status.stored_files) {
                m_decryptRecord->addItem(QString::fromStdString(name));
            }
            if (status.stored_files.empty()) {
                m_decryptRecord->addItem("No protected records yet");
                m_decryptRecord->setEnabled(false);
            } else {
                m_decryptRecord->setEnabled(true);
            }
            m_decryptButton->setEnabled(m_vaultInitialized && !status.stored_files.empty());
            m_encryptButton->setEnabled(m_vaultInitialized);
            if (!m_vaultInitialized) {
                m_resultLabel->setText("Initialize this vault before encrypting or decrypting files.");
            }
        } catch (const std::exception& error) {
            m_vaultInitialized = false;
            m_vaultState->setText("Vault status unavailable");
            m_engineState->setText(QString::fromUtf8(error.what()));
            m_initializeButton->setEnabled(false);
            m_encryptButton->setEnabled(false);
            m_decryptButton->setEnabled(false);
        }
    }

    void initializeVault() {
        if (m_vaultPath->text().trimmed().isEmpty()) {
            QMessageBox::warning(this, "Vault path required", "Choose a directory for the vault first.");
            return;
        }
        if (QMessageBox::question(this, "Initialize vault",
                "Create the vault directory and metadata at this location?\n\n" + m_vaultPath->text())
            != QMessageBox::Yes) {
            return;
        }
        const auto vaultPath = toPath(m_vaultPath->text());
        runTask("Initializing vault…", [vaultPath] {
            try {
                kvault::VaultManager vault(vaultPath);
                return vault.initializeVault()
                    ? QString("Vault initialized and ready at %1")
                        .arg(QString::fromStdString(vaultPath.string()))
                    : QString("Could not initialize the vault. Check the selected path and permissions.");
            } catch (const std::exception& error) {
                return QString("Vault initialization failed: %1").arg(QString::fromUtf8(error.what()));
            }
        });
    }

    void encryptSelectedFile() {
        const QString source = m_encryptInput->text();
        if (source.isEmpty() || m_encryptPassword->text().isEmpty()) {
            QMessageBox::warning(this, "Missing information", "Select a file and enter a passphrase.");
            return;
        }
        std::string secret = m_encryptPassword->text().toUtf8().toStdString();
        m_encryptPassword->clear();
        const auto vaultPath = toPath(m_vaultPath->text());
        const auto sourcePath = toPath(source);
        const QString filename = QFileInfo(source).fileName();
        runTask("Encrypting and authenticating the selected file…",
                [vaultPath, sourcePath, filename, secret = std::move(secret)]() mutable {
            try {
                kvault::VaultManager vault(vaultPath);
                const bool success = vault.encryptFile(sourcePath, secret);
                kvault::KeyDerivation::secureZero(secret.data(), secret.size());
                return success
                    ? QString("Encrypted and authenticated %1. The protected record is saved in the vault.")
                        .arg(filename)
                    : QString("Encryption failed. Check the source file, vault path, and permissions.");
            } catch (const std::exception& error) {
                kvault::KeyDerivation::secureZero(secret.data(), secret.size());
                return QString("Encryption failed: %1").arg(QString::fromUtf8(error.what()));
            }
        });
    }

    void decryptSelectedFile() {
        if (m_decryptRecord->currentIndex() < 0 || !m_decryptRecord->isEnabled() ||
            m_decryptOutput->text().trimmed().isEmpty() || m_decryptPassword->text().isEmpty()) {
            QMessageBox::warning(this, "Missing information",
                "Choose a protected record, an output path, and enter its passphrase.");
            return;
        }
        const std::string record = m_decryptRecord->currentText().toStdString();
        const auto vaultPath = toPath(m_vaultPath->text());
        const auto outputPath = toPath(m_decryptOutput->text());
        std::string secret = m_decryptPassword->text().toUtf8().toStdString();
        m_decryptPassword->clear();
        runTask("Verifying the record, then restoring plaintext…",
                [vaultPath, outputPath, record, secret = std::move(secret)]() mutable {
            try {
                kvault::VaultManager vault(vaultPath);
                const bool success = vault.decryptFile(record, outputPath, secret);
                kvault::KeyDerivation::secureZero(secret.data(), secret.size());
                return success
                    ? QString("Record authenticated and restored to %1")
                        .arg(QString::fromStdString(outputPath.string()))
                    : QString("Restore failed. The passphrase may be wrong or the record may be damaged.");
            } catch (const std::exception& error) {
                kvault::KeyDerivation::secureZero(secret.data(), secret.size());
                return QString("Restore failed: %1").arg(QString::fromUtf8(error.what()));
            }
        });
    }

    void runTask(const QString& progress, std::function<QString()> task) {
        setBusy(true);
        m_resultLabel->setText(progress);
        auto* worker = QThread::create([this, task = std::move(task)]() mutable {
            const QString result = task();
            QMetaObject::invokeMethod(this, [this, result] {
                m_resultLabel->setText(result);
            }, Qt::QueuedConnection);
        });
        worker->setParent(this);
        m_worker = worker;
        connect(worker, &QThread::finished, this, [this, worker] {
            if (m_worker == worker) {
                m_worker = nullptr;
            }
            setBusy(false);
            refreshVaultState();
            worker->deleteLater();
        });
        worker->start();
    }

    void setBusy(bool busy) {
        m_vaultPath->setEnabled(!busy);
        m_initializeButton->setEnabled(!busy && !m_vaultInitialized);
        m_tabs->setEnabled(!busy);
        if (busy) {
            m_vaultState->setText("Operation in progress…");
        }
    }
};

} // namespace

int main(int argc, char* argv[]) {
    QApplication app(argc, argv);
    app.setApplicationName("KernelVault");
    app.setOrganizationName("KernelVault Capstone");

    MainWindow window;
    window.show();
    return app.exec();
}
