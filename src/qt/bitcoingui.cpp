/*
 * Qt4 bitcoin GUI.
 *
 * W.J. van der Laan 2011-2012
 * The Bitcoin Developers 2011-2012
 */
#include "bitcoingui.h"
#include "transactiontablemodel.h"
#include "addressbookpage.h"
#include "messagepage.h"
#include "invoicepage.h"
#include "receiptpage.h"
#include "sendcoinsdialog.h"
#include "votecoinsdialog.h"
#include "votingdialog.h"
#include "sendmessagesdialog.h"
#include "signverifymessagedialog.h"
#include "optionsdialog.h"
#include "aboutdialog.h"
#include "clientmodel.h"
#include "walletmodel.h"
#include "messagemodel.h"
#include "ircmodel.h"
#include "editaddressdialog.h"
#include "optionsmodel.h"
#include "transactiondescdialog.h"
#include "addresstablemodel.h"
#include "transactionview.h"
#include "overviewpage.h"
#include "bitcoinunits.h"
#include "guiconstants.h"
#include "askpassphrasedialog.h"
#include "notificator.h"
#include "guiutil.h"
#include "ui_interface.h"
#include "rpcconsole.h"
#include "wallet.h"
#include "init.h"
#include "bitcoinrpc.h"

#ifdef Q_OS_MAC
#include "macdockiconhandler.h"
#endif

#include <QApplication>
#include <QMainWindow>
#include <QMenuBar>
#include <QMenu>
#include <QIcon>
#include <QTabWidget>
#include <QVBoxLayout>
#include <QToolBar>
#include <QStatusBar>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QLocale>
#include <QMessageBox>
#include <QMimeData>
#include <QProgressBar>
#include <QStackedWidget>
#include <QDateTime>
#include <QMovie>
#include <QFileDialog>
#include <QDesktopServices>
#include <QTimer>
#include <QDragEnterEvent>
#include <QUrl>
#include <QStyle>

#include <iostream>

BitcoinGUI::BitcoinGUI(QWidget *parent):
    QMainWindow(parent),
    clientModel(0),
    walletModel(0),
    messageModel(0),
    ircModel(0),
    encryptWalletAction(0),
    changePassphraseAction(0),
	miningOffAction(0),
    miningOneAction(0),
    miningTwoAction(0),
    miningThreeAction(0),
    miningFourAction(0),
    currentVotesAction(0),
    currentCandidatesAction(0),
    howToVoteAction(0),
    currentResultsAction(0),
    aboutQtAction(0),
    trayIcon(0),
    notificator(0),
    rpcConsole(0)
{
    resize(850, 550);
    setWindowTitle(tr("NoirShares") + " - " + tr("Wallet"));

    this->setStyleSheet("QMainWindow {background-color: black; color: white;} "
#ifndef Q_OS_MAC
                        "QToolButton {background-color: black; color: white;} "
                        "QToolButton:hover {background-color: black; color: #ffff77;} "
                        "QToolButton:pressed {background-color: #0000bb; color: white;} "
                        "QToolButton:checked {background-color: #000099; color: white;} "
                        "QToolButton:disabled {background-color: #333333; color: white;} "
#endif
                        "QComboBox {border:1px solid white; border-radius: 3px; min-width: 5em; "
                        "           color:white; background-color:black;} "
                        "QComboBox::drop-down {border: 0px;} "
                        "QComboBox * {color: black;} "
                        "QComboBox:on {color: black} "
                        "QComboBox:on *:hover {background-color: blue} "
                        "QMessageBox QLabel {color: black;} "
                        "AddressBookPage {background-color: black; border-color: white;"
                        "                          color: white; border-width: 1px;} "
                        "TransactionView {background-color: black; color: white;} "
                        "transactionView {background-color: black; color: white;} "
                        "QLabel {color: white;} "
                        "QHeaderView::section{background-color: black; border-color:white;"
                        "                     color: white; font-weight:bold;"
                        "                     border-width: 1px; border-style: solid;} "
                        "QValidatedLineEdit {border-style: solid; border-width: 1px;"
                        "                    border-color: white;}"
                        "QDoubleSpinBox {color:white;background-color:#222222; "
                        "                border-color:white;border-width:1px;font-weight:bold;} "
                        "QLineEdit {border-style: solid; border-width: 1px;"
                        "           border-color: white;}"
                    
                       );


    
    
#ifndef Q_OS_MAC
    qApp->setWindowIcon(QIcon(":icons/bitcoin"));
    setWindowIcon(QIcon(":icons/bitcoin"));
#else
    setUnifiedTitleAndToolBarOnMac(true);
    QApplication::setAttribute(Qt::AA_DontShowIconsInMenus);
#endif
    // Accept D&D of URIs
    setAcceptDrops(true);

    // Create actions for the toolbar, menu bar and tray/dock icon
    createActions();

    // Create application menu bar
    createMenuBar();

    // Create the toolbars
    createToolBars();

    // Create the tray icon (or setup the dock icon)
    createTrayIcon();

    // Create tabs
    overviewPage = new OverviewPage();

    transactionsPage = new QWidget(this);
    QVBoxLayout *vbox = new QVBoxLayout();
    transactionView = new TransactionView(this);
    vbox->addWidget(transactionView);
    transactionsPage->setLayout(vbox);

    addressBookPage = new AddressBookPage(AddressBookPage::ForEditing, AddressBookPage::SendingTab);

    receiveCoinsPage = new AddressBookPage(AddressBookPage::ForEditing, AddressBookPage::ReceivingTab);

    messagePage = new MessagePage();
    invoicePage = new InvoicePage();
    
    voteCoinsPage = new VoteCoinsDialog();
	votingPage = new VotingDialog();
    receiptPage = new ReceiptPage();

    sendCoinsPage = new SendCoinsDialog(this);

    sendMessagesPage     = new SendMessagesDialog(SendMessagesDialog::Encrypted, SendMessagesDialog::Page, this);
    sendMessagesAnonPage = new SendMessagesDialog(SendMessagesDialog::Anonymous, SendMessagesDialog::Page, this);

    signVerifyMessageDialog = new SignVerifyMessageDialog(this);

    centralWidget = new QStackedWidget(this);
    centralWidget->addWidget(overviewPage);
    centralWidget->addWidget(transactionsPage);
    centralWidget->addWidget(addressBookPage);
    centralWidget->addWidget(receiveCoinsPage);
    centralWidget->addWidget(sendCoinsPage);
    centralWidget->addWidget(sendMessagesPage);
    centralWidget->addWidget(sendMessagesAnonPage);
    centralWidget->addWidget(messagePage);
    centralWidget->addWidget(invoicePage);
    centralWidget->addWidget(receiptPage);
    centralWidget->addWidget(voteCoinsPage);
    centralWidget->addWidget(votingPage);
    setCentralWidget(centralWidget);

    // Create status bar
    statusBar();

    // Status bar notification icons
    QFrame *frameBlocks = new QFrame();
    frameBlocks->setContentsMargins(0,0,0,0);
    frameBlocks->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Preferred);
    QHBoxLayout *frameBlocksLayout = new QHBoxLayout(frameBlocks);
    frameBlocksLayout->setContentsMargins(3,0,3,0);
    frameBlocksLayout->setSpacing(3);
    labelEncryptionIcon = new QLabel();
    labelStakingIcon = new QLabel();
    labelConnectionsIcon = new QLabel();
    labelBlocksIcon = new QLabel();
    frameBlocksLayout->addStretch();
    frameBlocksLayout->addWidget(labelEncryptionIcon);
    frameBlocksLayout->addStretch();
    frameBlocksLayout->addWidget(labelStakingIcon);
    frameBlocksLayout->addStretch();
    frameBlocksLayout->addWidget(labelConnectionsIcon);
    frameBlocksLayout->addStretch();
    frameBlocksLayout->addWidget(labelBlocksIcon);
    frameBlocksLayout->addStretch();

    // Progress bar and label for blocks download
    progressBarLabel = new QLabel();
    progressBarLabel->setVisible(false);
    progressBar = new QProgressBar();
    progressBar->setAlignment(Qt::AlignCenter);
    progressBar->setVisible(false);

    // Override style sheet for progress bar for styles that have a segmented progress bar,
    // as they make the text unreadable (workaround for issue #1071)
    // See https://qt-project.org/doc/qt-4.8/gallery.html
    QString curStyle = qApp->style()->metaObject()->className();
    if(curStyle == "QWindowsStyle" || curStyle == "QWindowsXPStyle")
    {
        progressBar->setStyleSheet("QProgressBar { background-color: #e8e8e8; border: 1px solid grey; border-radius: 7px; padding: 1px; text-align: center; } QProgressBar::chunk { background: QLinearGradient(x1: 0, y1: 0, x2: 1, y2: 0, stop: 0 #FF8000, stop: 1 orange); border-radius: 7px; margin: 0px; }");
    }

    statusBar()->addWidget(progressBarLabel);
    statusBar()->addWidget(progressBar);
    statusBar()->addPermanentWidget(frameBlocks);

    syncIconMovie = new QMovie(":/movies/update_spinner", "mng", this);
	// this->setStyleSheet("background-color: #ceffee;");

    // Clicking on a transaction on the overview page simply sends you to transaction history page
    connect(overviewPage, SIGNAL(transactionClicked(QModelIndex)), this, SLOT(gotoHistoryPage()));
    connect(overviewPage, SIGNAL(transactionClicked(QModelIndex)), transactionView, SLOT(focusTransaction(QModelIndex)));

    // Double-clicking on a transaction on the transaction history page shows details
    connect(transactionView, SIGNAL(doubleClicked(QModelIndex)), transactionView, SLOT(showDetails()));

    rpcConsole = new RPCConsole(this);
    connect(openRPCConsoleAction, SIGNAL(triggered()), rpcConsole, SLOT(show()));

    // Clicking on "Verify Message" in the address book sends you to the verify message tab
    connect(addressBookPage, SIGNAL(verifyMessage(QString)), this, SLOT(gotoVerifyMessageTab(QString)));
    // Clicking on "Sign Message" in the receive coins page sends you to the sign message tab
    connect(receiveCoinsPage, SIGNAL(signMessage(QString)), this, SLOT(gotoSignMessageTab(QString)));

    gotoOverviewPage();
}

BitcoinGUI::~BitcoinGUI()
{
    if(trayIcon) // Hide tray icon, as deleting will let it linger until quit (on Ubuntu)
        trayIcon->hide();
#ifdef Q_OS_MAC
    delete appMenuBar;
#endif
}

void BitcoinGUI::createActions()
{
    QActionGroup *tabGroup = new QActionGroup(this);

    overviewAction = new QAction(QIcon(":/icons/overview"), tr("&Overview"), this);
    overviewAction->setToolTip(tr("Show general overview of wallet"));
    overviewAction->setCheckable(true);
    overviewAction->setShortcut(QKeySequence(Qt::ALT + Qt::Key_1));
    tabGroup->addAction(overviewAction);

    sendCoinsAction = new QAction(QIcon(":/icons/send"), tr("&Send coins"), this);
    sendCoinsAction->setToolTip(tr("Send coins to a NoirShares address"));
    sendCoinsAction->setCheckable(true);
    sendCoinsAction->setShortcut(QKeySequence(Qt::ALT + Qt::Key_2));
    tabGroup->addAction(sendCoinsAction);

    receiveCoinsAction = new QAction(QIcon(":/icons/receiving_addresses"), tr("&Receive coins"), this);
    receiveCoinsAction->setToolTip(tr("Show the list of addresses for receiving payments"));
    receiveCoinsAction->setCheckable(true);
    receiveCoinsAction->setShortcut(QKeySequence(Qt::ALT + Qt::Key_3));
    tabGroup->addAction(receiveCoinsAction);

    historyAction = new QAction(QIcon(":/icons/history"), tr("&Transactions"), this);
    historyAction->setToolTip(tr("Browse transaction history"));
    historyAction->setCheckable(true);
    historyAction->setShortcut(QKeySequence(Qt::ALT + Qt::Key_4));
    tabGroup->addAction(historyAction);

    addressBookAction = new QAction(QIcon(":/icons/address-book"), tr("&Address Book"), this);
    addressBookAction->setToolTip(tr("Edit the list of stored addresses and labels"));
    addressBookAction->setCheckable(true);
    addressBookAction->setShortcut(QKeySequence(Qt::ALT + Qt::Key_5));
    tabGroup->addAction(addressBookAction);

    sendMessagesAction = new QAction(QIcon(":/icons/em"), tr("Send &Messages"), this);
    sendMessagesAction->setToolTip(tr("Send Encrypted Messages"));
    sendMessagesAction->setCheckable(true);
    sendMessagesAction->setShortcut(QKeySequence(Qt::ALT + Qt::Key_6));
    tabGroup->addAction(sendMessagesAction);

    messageAction = new QAction(QIcon(":/icons/em"), tr("Mess&ages"), this);
    messageAction->setToolTip(tr("Encrypted Messaging"));
    messageAction->setCheckable(true);
    messageAction->setShortcut(QKeySequence(Qt::ALT + Qt::Key_6));
    tabGroup->addAction(messageAction);

    invoiceAction = new QAction(QIcon(":/icons/assets"), tr("&Invoices"), this);
    invoiceAction->setToolTip(tr("Encrypted Invoicing"));
    invoiceAction->setCheckable(true);
    invoiceAction->setShortcut(QKeySequence(Qt::ALT + Qt::Key_7));
    tabGroup->addAction(invoiceAction);

    receiptAction = new QAction(QIcon(":/icons/assets"), tr("Re&ceipts"), this);
    receiptAction->setToolTip(tr("Encrypted Receipting"));
    receiptAction->setCheckable(true);
    receiptAction->setShortcut(QKeySequence(Qt::ALT + Qt::Key_8));
    tabGroup->addAction(receiptAction);

    sendMessagesAnonAction = new QAction(QIcon(":/icons/em"), tr("NoirTal&k "), this);
    sendMessagesAnonAction->setToolTip(tr("Send Anonymous Message"));
    sendMessagesAnonAction->setCheckable(true);
    sendMessagesAnonAction->setShortcut(QKeySequence(Qt::ALT + Qt::Key_9));
    tabGroup->addAction(sendMessagesAnonAction);

    sendCoinsAnonAction = new QAction(QIcon(":/icons/em"), tr("Zero Se&nd (coming soon)"), this);
    sendCoinsAnonAction->setToolTip(tr("Send Coins Anonymously (being researched for stable viable implementation)"));
    sendCoinsAnonAction->setCheckable(false); // TODO: Set to true once Anonymous messaging and transactions have been implemented
    sendCoinsAnonAction->setEnabled(false); // TODO: Remove once Anonymous messaging and transactions have been implemented
    tabGroup->addAction(sendCoinsAnonAction);

    voteCoinsAction = new QAction(QIcon(":/icons/lotto"), tr("L&otto"), this);
    voteCoinsAction->setToolTip(tr("Play Lottey (still under development, likely to be part of phase two deployment)"));
    voteCoinsAction->setCheckable(false); 
    voteCoinsAction->setShortcut(QKeySequence(Qt::ALT + Qt::Key_9)); 
    tabGroup->addAction(voteCoinsAction);
    
	votingAction = new QAction(QIcon(":/icons/voting_prefs"), tr("&Vote"), this);
    votingAction->setToolTip(tr("Vote for company officer"));
    votingAction->setCheckable(true);
    votingAction->setShortcut(QKeySequence(Qt::ALT + Qt::Key_6));
    tabGroup->addAction(votingAction);

    connect(overviewAction, SIGNAL(triggered()), this, SLOT(showNormalIfMinimized()));
    connect(overviewAction, SIGNAL(triggered()), this, SLOT(gotoOverviewPage()));
    connect(sendCoinsAction, SIGNAL(triggered()), this, SLOT(showNormalIfMinimized()));
    connect(sendCoinsAction, SIGNAL(triggered()), this, SLOT(gotoSendCoinsPage()));
    connect(receiveCoinsAction, SIGNAL(triggered()), this, SLOT(showNormalIfMinimized()));
    connect(receiveCoinsAction, SIGNAL(triggered()), this, SLOT(gotoReceiveCoinsPage()));
    connect(historyAction, SIGNAL(triggered()), this, SLOT(showNormalIfMinimized()));
    connect(historyAction, SIGNAL(triggered()), this, SLOT(gotoHistoryPage()));
    connect(addressBookAction, SIGNAL(triggered()), this, SLOT(showNormalIfMinimized()));
    connect(addressBookAction, SIGNAL(triggered()), this, SLOT(gotoAddressBookPage()));
    connect(sendMessagesAction, SIGNAL(triggered()), this, SLOT(showNormalIfMinimized()));
    connect(sendMessagesAction, SIGNAL(triggered()), this, SLOT(gotoSendMessagesPage()));
    connect(messageAction, SIGNAL(triggered()), this, SLOT(showNormalIfMinimized()));
    connect(messageAction, SIGNAL(triggered()), this, SLOT(gotoMessagesPage()));
    connect(invoiceAction, SIGNAL(triggered()), this, SLOT(showNormalIfMinimized()));
    connect(invoiceAction, SIGNAL(triggered()), this, SLOT(gotoInvoicesPage()));
    connect(receiptAction, SIGNAL(triggered()), this, SLOT(showNormalIfMinimized()));
    connect(receiptAction, SIGNAL(triggered()), this, SLOT(gotoReceiptPage()));
    connect(sendMessagesAnonAction, SIGNAL(triggered()), this, SLOT(showNormalIfMinimized()));
    connect(sendMessagesAnonAction, SIGNAL(triggered()), this, SLOT(gotoSendMessagesAnonPage()));
    connect(sendCoinsAnonAction, SIGNAL(triggered()), this, SLOT(showNormalIfMinimized()));
    connect(sendCoinsAnonAction, SIGNAL(triggered()), this, SLOT(gotoAddressBookPage()));
    connect(voteCoinsAction, SIGNAL(triggered()), this, SLOT(showNormalIfMinimized()));
    connect(voteCoinsAction, SIGNAL(triggered()), this, SLOT(gotoVoteCoinsPage()));
    connect(votingAction, SIGNAL(triggered()), this, SLOT(showNormalIfMinimized()));
    connect(votingAction, SIGNAL(triggered()), this, SLOT(gotoVotingPage()));


    quitAction = new QAction(QIcon(":/icons/quit"), tr("E&xit"), this);
    quitAction->setToolTip(tr("Quit application"));
    quitAction->setShortcut(QKeySequence(Qt::CTRL + Qt::Key_Q));
    quitAction->setMenuRole(QAction::QuitRole);
    aboutAction = new QAction(QIcon(":/icons/bitcoin"), tr("&About NoirShares"), this);
    aboutAction->setToolTip(tr("Show information about NoirShares"));
    aboutAction->setMenuRole(QAction::AboutRole);
    aboutQtAction = new QAction(QIcon(":/trolltech/qmessagebox/images/qtlogo-64.png"), tr("About &Qt"), this);
    aboutQtAction->setToolTip(tr("Show information about Qt"));
    aboutQtAction->setMenuRole(QAction::AboutQtRole);
    optionsAction = new QAction(QIcon(":/icons/options"), tr("&Options..."), this);
    optionsAction->setToolTip(tr("Modify configuration options for NoirShares"));
    optionsAction->setMenuRole(QAction::PreferencesRole);
    toggleHideAction = new QAction(QIcon(":/icons/bitcoin"), tr("&Show / Hide"), this);
    encryptWalletAction = new QAction(QIcon(":/icons/lock_closed"), tr("&Encrypt Wallet..."), this);
    encryptWalletAction->setToolTip(tr("Encrypt or decrypt wallet"));
    encryptWalletAction->setCheckable(true);
    backupWalletAction = new QAction(QIcon(":/icons/filesave"), tr("&Backup Wallet..."), this);
    backupWalletAction->setToolTip(tr("Backup wallet to another location"));
    dumpWalletAction = new QAction(QIcon(":/icons/dump"), tr("&Dump Wallet..."), this);
    dumpWalletAction->setStatusTip(tr("Export wallet's keys to a text file"));
    importWalletAction = new QAction(QIcon(":/icons/import"), tr("&Import Wallet..."), this);
    importWalletAction->setStatusTip(tr("Import a file's keys into a wallet"));
    changePassphraseAction = new QAction(QIcon(":/icons/key"), tr("&Change Passphrase..."), this);
    changePassphraseAction->setToolTip(tr("Change the passphrase used for wallet encryption"));
    unlockWalletAction = new QAction(QIcon(":/icons/lock_open"), tr("&Unlock Wallet..."), this);
    unlockWalletAction->setToolTip(tr("Unlock wallet"));
    lockWalletAction = new QAction(QIcon(":/icons/lock_closed"), tr("&Lock Wallet"), this);
    lockWalletAction->setToolTip(tr("Lock wallet"));
	miningOffAction = new QAction(QIcon(":/icons/mining_inactive"), tr("Solo Mining Off"), this);
    miningOffAction->setStatusTip(tr("Stop Mining. May take some time to wind down."));
    miningOneAction = new QAction(QIcon(":/icons/mining_active"), tr("Solo Mining On (1GB Required)"), this);
    miningOneAction->setStatusTip(tr("Mine with 1 process - not recommended!"));
    miningTwoAction = new QAction(QIcon(":/icons/mining"), tr("Mine 2 Processes ( ~1.5GB Required)"), this);
    miningTwoAction->setStatusTip(tr("Mine with 2 processes. ~2GB Required."));
    miningThreeAction = new QAction(QIcon(":/icons/mining"), tr("Mine 4 Processes (3.5GB Required)"), this);
    miningThreeAction->setStatusTip(tr("Mine MemoryCoin with 4 processes. ~3.5GB Required."));
    miningFourAction = new QAction(QIcon(":/icons/mining"), tr("Mine all cores/threads Processes (~750MB Required per thread)"), this);
    miningFourAction->setStatusTip(tr("Mine with all cores/threads. ~750MB Required per thread."));
	currentVotesAction = new QAction(QIcon(":/icons/voting_prefs"), tr("Current Voting Preferences"), this);
    currentVotesAction->setStatusTip(tr("Show who or what you are currently voting for. (Web)"));
    currentCandidatesAction = new QAction(QIcon(":/icons/voting_candidates"), tr("Current Candidates"), this);
    currentCandidatesAction->setStatusTip(tr("Display a list of current candidates. (Web)"));
    howToVoteAction = new QAction(QIcon(":/icons/voting_how"), tr("How To Vote"), this);
    howToVoteAction->setStatusTip(tr("Information about how to cast your vote. (Web)"));
    currentResultsAction = new QAction(QIcon(":/icons/voting_results"), tr("Latest Election Results"), this);
    currentResultsAction->setStatusTip(tr("Current board and past results. (Web)")); 
    signMessageAction = new QAction(QIcon(":/icons/edit"), tr("Sign &message..."), this);
    verifyMessageAction = new QAction(QIcon(":/icons/transaction_0"), tr("&Verify message..."), this);

    exportAction = new QAction(QIcon(":/icons/export"), tr("&Export..."), this);
    exportAction->setToolTip(tr("Export the data in the current tab to a file"));
    openRPCConsoleAction = new QAction(QIcon(":/icons/debugwindow"), tr("&Debug window"), this);
    openRPCConsoleAction->setToolTip(tr("Open debugging and diagnostic console"));

    connect(quitAction, SIGNAL(triggered()), qApp, SLOT(quit()));
    connect(aboutAction, SIGNAL(triggered()), this, SLOT(aboutClicked()));
    connect(aboutQtAction, SIGNAL(triggered()), qApp, SLOT(aboutQt()));
    connect(optionsAction, SIGNAL(triggered()), this, SLOT(optionsClicked()));
    connect(toggleHideAction, SIGNAL(triggered()), this, SLOT(toggleHidden()));
    connect(encryptWalletAction, SIGNAL(triggered(bool)), this, SLOT(encryptWallet(bool)));
    connect(backupWalletAction, SIGNAL(triggered()), this, SLOT(backupWallet()));
    connect(dumpWalletAction, SIGNAL(triggered()), this, SLOT(dumpWallet()));
    connect(importWalletAction, SIGNAL(triggered()), this, SLOT(importWallet()));
    connect(changePassphraseAction, SIGNAL(triggered()), this, SLOT(changePassphrase()));
    connect(unlockWalletAction, SIGNAL(triggered()), this, SLOT(unlockWallet()));
    connect(lockWalletAction, SIGNAL(triggered()), this, SLOT(lockWallet()));
	connect(miningOffAction, SIGNAL(triggered()), this, SLOT(miningOff()));
    connect(miningOneAction, SIGNAL(triggered()), this, SLOT(miningOne()));
    connect(miningTwoAction, SIGNAL(triggered()), this, SLOT(miningTwo()));
    connect(miningThreeAction, SIGNAL(triggered()), this, SLOT(miningThree()));
    connect(miningFourAction, SIGNAL(triggered()), this, SLOT(miningFour()));
	connect(currentVotesAction, SIGNAL(triggered()), this, SLOT(currentVotes()));    
    connect(currentCandidatesAction, SIGNAL(triggered()), this, SLOT(currentCandidates()));    
    connect(howToVoteAction, SIGNAL(triggered()), this, SLOT(howToVote()));    
    connect(currentResultsAction, SIGNAL(triggered()), this, SLOT(currentResults()));
    connect(signMessageAction, SIGNAL(triggered()), this, SLOT(gotoSignMessageTab()));
    connect(verifyMessageAction, SIGNAL(triggered()), this, SLOT(gotoVerifyMessageTab()));
}

void BitcoinGUI::createMenuBar()
{
#ifdef Q_OS_MAC
    // Create a decoupled menu bar on Mac which stays even if the window is closed
    appMenuBar = new QMenuBar();
#else
    // Get the main window's menu bar on other platforms
    appMenuBar = menuBar();
#endif

    // Configure the menus
    QMenu *file = appMenuBar->addMenu(tr("&File"));
    file->addAction(backupWalletAction);
    file->addAction(exportAction);
    file->addSeparator();
    file->addAction(dumpWalletAction);
    file->addAction(importWalletAction);
    file->addAction(signMessageAction);
    file->addAction(verifyMessageAction);
    file->addSeparator();
    file->addAction(quitAction);

    QMenu *settings = appMenuBar->addMenu(tr("&Settings"));
    settings->addAction(encryptWalletAction);
    settings->addAction(changePassphraseAction);
    settings->addAction(unlockWalletAction);
    settings->addAction(lockWalletAction);
    settings->addSeparator();
    settings->addAction(optionsAction);

	QMenu *mining = appMenuBar->addMenu(tr("&Mining"));
    mining->addSeparator();
    mining->addAction(miningOneAction);
    mining->addAction(miningOffAction);
    mining->addAction(miningTwoAction);
    mining->addAction(miningThreeAction);
    mining->addAction(miningFourAction);
    
	QMenu *voting = appMenuBar->addMenu(tr("&Voting"));
    voting->addAction(currentVotesAction);
    voting->addAction(currentCandidatesAction);
    voting->addAction(howToVoteAction);
    voting->addAction(currentResultsAction);


    QMenu *help = appMenuBar->addMenu(tr("&Help"));
    help->addAction(openRPCConsoleAction);
    help->addSeparator();
    help->addAction(aboutAction);
    help->addAction(aboutQtAction);
}

void BitcoinGUI::createToolBars()
{
    QToolBar *toolbar = new QToolBar(tr("Main toolbar"));

    addToolBar(Qt::LeftToolBarArea, toolbar);
    toolbar->setAllowedAreas(Qt::TopToolBarArea | Qt::LeftToolBarArea | Qt::RightToolBarArea | Qt::BottomToolBarArea);
    toolbar->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);
    toolbar->addAction(overviewAction);
    toolbar->addAction(sendCoinsAction);
    toolbar->addAction(receiveCoinsAction);
    toolbar->addAction(historyAction);
    toolbar->addAction(addressBookAction);
    toolbar->addSeparator();

    QLabel* enc_lbl = new QLabel();
    enc_lbl->setText("NoirEncryption");
    enc_lbl->setAlignment(Qt::AlignHCenter);

    toolbar->addWidget(enc_lbl);
    toolbar->addAction(sendMessagesAction);
    toolbar->addAction(messageAction);
    toolbar->addAction(invoiceAction);
    toolbar->addAction(receiptAction);
    toolbar->addSeparator();

    QLabel* anon_lbl = new QLabel();
    anon_lbl->setText("NoirSpace");
    anon_lbl->setAlignment(Qt::AlignHCenter);

    toolbar->addWidget(anon_lbl);

    toolbar->addAction(sendMessagesAnonAction);
    toolbar->addAction(sendCoinsAnonAction);
    toolbar->addAction(voteCoinsAction);
	
    toolbar->addSeparator();
    toolbar->addAction(exportAction);
    toolbar->addAction(votingAction);

    foreach(QAction *action, toolbar->actions()) {
        toolbar->widgetForAction(action)->setFixedWidth(200);
    }
}

void BitcoinGUI::setClientModel(ClientModel *clientModel)
{
    this->clientModel = clientModel;
    if(clientModel)
    {
        // Replace some strings and icons, when using the testnet
        if(clientModel->isTestNet())
        {
            setWindowTitle(windowTitle() + QString(" ") + tr("[testnet]"));
#ifndef Q_OS_MAC
            qApp->setWindowIcon(QIcon(":icons/bitcoin_testnet"));
            setWindowIcon(QIcon(":icons/bitcoin_testnet"));
#else
            MacDockIconHandler::instance()->setIcon(QIcon(":icons/bitcoin_testnet"));
#endif
            if(trayIcon)
            {
                trayIcon->setToolTip(tr("NoirShares client") + QString(" ") + tr("[testnet]"));
                trayIcon->setIcon(QIcon(":/icons/toolbar_testnet"));
                toggleHideAction->setIcon(QIcon(":/icons/toolbar_testnet"));
            }

            aboutAction->setIcon(QIcon(":/icons/toolbar_testnet"));
        }

        // Keep up to date with client
        setNumConnections(clientModel->getNumConnections());
        connect(clientModel, SIGNAL(numConnectionsChanged(int)), this, SLOT(setNumConnections(int)));

        setNumBlocks(clientModel->getNumBlocks(), clientModel->getNumBlocksOfPeers());
        connect(clientModel, SIGNAL(numBlocksChanged(int,int)), this, SLOT(setNumBlocks(int,int)));

        // Report errors from network/worker thread
        connect(clientModel, SIGNAL(error(QString,QString,bool)), this, SLOT(error(QString,QString,bool)));

        rpcConsole->setClientModel(clientModel);
        addressBookPage->setOptionsModel(clientModel->getOptionsModel());
        receiveCoinsPage->setOptionsModel(clientModel->getOptionsModel());
    }
}

void BitcoinGUI::setWalletModel(WalletModel *walletModel)
{
    this->walletModel = walletModel;
    if(walletModel)
    {
        // Report errors from wallet thread
        connect(walletModel, SIGNAL(error(QString,QString,bool)), this, SLOT(error(QString,QString,bool)));

        // Put transaction list in tabs
        transactionView->setModel(walletModel);

        overviewPage->setModel(walletModel);
        addressBookPage->setModel(walletModel->getAddressTableModel());
        receiveCoinsPage->setModel(walletModel->getAddressTableModel());
        sendCoinsPage->setModel(walletModel);
        signVerifyMessageDialog->setModel(walletModel);

        setEncryptionStatus(walletModel->getEncryptionStatus());
        connect(walletModel, SIGNAL(encryptionStatusChanged(int)), this, SLOT(setEncryptionStatus(int)));
		//VoteCoinsPage->setModel(walletModel);
        // Balloon pop-up for new transaction
        connect(walletModel->getTransactionTableModel(), SIGNAL(rowsInserted(QModelIndex,int,int)),
                this, SLOT(incomingTransaction(QModelIndex,int,int)));

        // Ask for passphrase if needed
        connect(walletModel, SIGNAL(requireUnlock()), this, SLOT(unlockWallet()));
    }
}

void BitcoinGUI::setMessageModel(MessageModel *messageModel)
{
    this->messageModel = messageModel;
    if(messageModel)
    {
        // Report errors from wallet thread
        connect(messageModel, SIGNAL(error(QString,QString,bool)), this, SLOT(error(QString,QString,bool)));

        messagePage->setModel(messageModel);
        invoicePage->setModel(messageModel);
        receiptPage->setModel(messageModel);
        sendMessagesPage->setModel(messageModel);
        sendMessagesAnonPage->setModel(messageModel);

        // Balloon pop-up for new message
        connect(messageModel, SIGNAL(rowsInserted(QModelIndex,int,int)),
                this, SLOT(incomingMessage(QModelIndex,int,int)));

    }
}

void BitcoinGUI::setIRCModel(IRCModel *ircModel)
{
    this->ircModel = ircModel;

    if(ircModel)
    {
        // Report errors from wallet thread
        connect(ircModel, SIGNAL(error(QString,QString,bool)), this, SLOT(error(QString,QString,bool)));

        overviewPage->setIRCModel(ircModel);

        /*
        // Balloon pop-up for new message
        connect(ircModel, SIGNAL(rowsInserted(QModelIndex,int,int)),
                this, SLOT(incomingMessage(QModelIndex,int,int)));
                */
    }
}

void BitcoinGUI::createTrayIcon()
{
    QMenu *trayIconMenu;
#ifndef Q_OS_MAC
    trayIcon = new QSystemTrayIcon(this);
    trayIconMenu = new QMenu(this);
    trayIcon->setContextMenu(trayIconMenu);
    trayIcon->setToolTip(tr("NoirShares client"));
    trayIcon->setIcon(QIcon(":/icons/toolbar"));
    connect(trayIcon, SIGNAL(activated(QSystemTrayIcon::ActivationReason)),
            this, SLOT(trayIconActivated(QSystemTrayIcon::ActivationReason)));
    trayIcon->show();
#else
    // Note: On Mac, the dock icon is used to provide the tray's functionality.
    MacDockIconHandler *dockIconHandler = MacDockIconHandler::instance();
    dockIconHandler->setMainWindow((QMainWindow *)this);
    trayIconMenu = dockIconHandler->dockMenu();
#endif

    // Configuration of the tray icon (or dock icon) icon menu
    trayIconMenu->addAction(toggleHideAction);
    trayIconMenu->addSeparator();
    trayIconMenu->addAction(sendCoinsAction);
    trayIconMenu->addAction(receiveCoinsAction);
    trayIconMenu->addSeparator();
    trayIconMenu->addAction(messageAction);
    trayIconMenu->addAction(voteCoinsAction);
	trayIconMenu->addAction(votingAction);
    trayIconMenu->addSeparator();
    trayIconMenu->addAction(signMessageAction);
    trayIconMenu->addAction(verifyMessageAction);
    trayIconMenu->addSeparator();
    trayIconMenu->addAction(optionsAction);
    trayIconMenu->addAction(openRPCConsoleAction);
#ifndef Q_OS_MAC // This is built-in on Mac
    trayIconMenu->addSeparator();
    trayIconMenu->addAction(quitAction);
#endif

    notificator = new Notificator(qApp->applicationName(), trayIcon);
}

#ifndef Q_OS_MAC
void BitcoinGUI::trayIconActivated(QSystemTrayIcon::ActivationReason reason)
{
    if(reason == QSystemTrayIcon::Trigger)
    {
        // Click on system tray icon triggers show/hide of the main window
        toggleHideAction->trigger();
    }
}
#endif

void BitcoinGUI::optionsClicked()
{
    if(!clientModel || !clientModel->getOptionsModel())
        return;
    OptionsDialog dlg;
    dlg.setModel(clientModel->getOptionsModel());
    dlg.exec();
}

void BitcoinGUI::aboutClicked()
{
    AboutDialog dlg;
    dlg.setModel(clientModel);
    dlg.exec();
}

void BitcoinGUI::setNumConnections(int count)
{
    QString icon;
    switch(count)
    {
    case 0: icon = ":/icons/connect_0"; break;
    case 1: case 2: case 3: icon = ":/icons/connect_1"; break;
    case 4: case 5: case 6: icon = ":/icons/connect_2"; break;
    case 7: case 8: case 9: icon = ":/icons/connect_3"; break;
    default: icon = ":/icons/connect_4"; break;
    }
    labelConnectionsIcon->setPixmap(QIcon(icon).pixmap(STATUSBAR_ICONSIZE,STATUSBAR_ICONSIZE));
    labelConnectionsIcon->setToolTip(tr("%n active connection(s) to NoirShares network", "", count));
}

void BitcoinGUI::setNumBlocks(int count, int nTotalBlocks)
{
    // don't show / hide progress bar and its label if we have no connection to the network
    if (!clientModel || clientModel->getNumConnections() == 0)
    {
        progressBarLabel->setVisible(false);
        progressBar->setVisible(false);

        return;
    }

    QString strStatusBarWarnings = clientModel->getStatusBarWarnings();
    QString tooltip;

    if(count < nTotalBlocks)
    {
        int nRemainingBlocks = nTotalBlocks - count;
        float nPercentageDone = count / (nTotalBlocks * 0.01f);

        if (strStatusBarWarnings.isEmpty())
        {
            progressBarLabel->setText(tr("Synchronizing with network..."));
            progressBarLabel->setVisible(true);
            progressBar->setFormat(tr("~%n block(s) remaining", "", nRemainingBlocks));
            progressBar->setMaximum(nTotalBlocks);
            progressBar->setValue(count);
            progressBar->setVisible(true);
        }

        tooltip = tr("Downloaded %1 of %2 blocks of transaction history (%3% done).").arg(count).arg(nTotalBlocks).arg(nPercentageDone, 0, 'f', 2);
    }
    else
    {
        if (strStatusBarWarnings.isEmpty())
            progressBarLabel->setVisible(false);

        progressBar->setVisible(false);
        tooltip = tr("Downloaded %1 blocks of transaction history.").arg(count);
    }

    // Override progressBarLabel text and hide progress bar, when we have warnings to display
    if (!strStatusBarWarnings.isEmpty())
    {
        progressBarLabel->setText(strStatusBarWarnings);
        progressBarLabel->setVisible(true);
        progressBar->setVisible(false);
    }

	tooltip = tr("Current difficulty is %1.").arg(clientModel->GetDifficulty()) + QString("<br>") + tooltip;

    QDateTime lastBlockDate = clientModel->getLastBlockDate();
    int secs = lastBlockDate.secsTo(QDateTime::currentDateTime());
    QString text;

    // Represent time from last generated block in human readable text
    if(secs <= 0)
    {
        // Fully up to date. Leave text empty.
    }
    else if(secs < 60)
    {
        text = tr("%n second(s) ago","",secs);
    }
    else if(secs < 60*60)
    {
        text = tr("%n minute(s) ago","",secs/60);
    }
    else if(secs < 24*60*60)
    {
        text = tr("%n hour(s) ago","",secs/(60*60));
    }
    else
    {
        text = tr("%n day(s) ago","",secs/(60*60*24));
    }

    // Set icon state: spinning if catching up, tick otherwise
    if(secs < 90*60 && count >= nTotalBlocks)
    {
        tooltip = tr("Up to date") + QString(".<br>") + tooltip;
        labelBlocksIcon->setPixmap(QIcon(":/icons/synced").pixmap(STATUSBAR_ICONSIZE, STATUSBAR_ICONSIZE));

        overviewPage->showOutOfSyncWarning(false);
    }
    else
    {
        tooltip = tr("Catching up...") + QString("<br>") + tooltip;
        labelBlocksIcon->setMovie(syncIconMovie);
        syncIconMovie->start();

        overviewPage->showOutOfSyncWarning(true);
    }

    if(!text.isEmpty())
    {
        tooltip += QString("<br>");
        tooltip += tr("Last received block was generated %1.").arg(text);
    }

    // Don't word-wrap this (fixed-width) tooltip
    tooltip = QString("<nobr>") + tooltip + QString("</nobr>");

    labelBlocksIcon->setToolTip(tooltip);
    progressBarLabel->setToolTip(tooltip);
    progressBar->setToolTip(tooltip);
}

void BitcoinGUI::error(const QString &title, const QString &message, bool modal)
{
    // Report errors from network/worker thread
    if(modal)
    {
        QMessageBox::critical(this, title, message, QMessageBox::Ok, QMessageBox::Ok);
    } else {
        notificator->notify(Notificator::Critical, title, message);
    }
}

void BitcoinGUI::message(const QString &title, const QString &message, unsigned int style, const QString &detail)
{
    QString strTitle = tr("NovaCoin") + " - ";
    // Default to information icon
    int nMBoxIcon = QMessageBox::Information;
    int nNotifyIcon = Notificator::Information;


    // Check for usage of predefined title
    switch (style) {
    case CClientUIInterface::MSG_ERROR:
        strTitle += tr("Error");
        break;
    case CClientUIInterface::MSG_WARNING:
        strTitle += tr("Warning");
        break;
    case CClientUIInterface::MSG_INFORMATION:
        strTitle += tr("Information");
        break;
    default:
        strTitle += title; // Use supplied title
    }

    // Check for error/warning icon
    if (style & CClientUIInterface::ICON_ERROR) {
        nMBoxIcon = QMessageBox::Critical;
        nNotifyIcon = Notificator::Critical;
    }
    else if (style & CClientUIInterface::ICON_WARNING) {
        nMBoxIcon = QMessageBox::Warning;
        nNotifyIcon = Notificator::Warning;
    }

    // Display message
    if (style & CClientUIInterface::MODAL) {
        // Check for buttons, use OK as default, if none was supplied
        QMessageBox::StandardButton buttons;
        buttons = QMessageBox::Ok;

        QMessageBox mBox((QMessageBox::Icon)nMBoxIcon, strTitle, message, buttons);

        if(!detail.isEmpty()) { mBox.setDetailedText(detail); }

        mBox.exec();
    }
    else
        notificator->notify((Notificator::Class)nNotifyIcon, strTitle, message);
}

void BitcoinGUI::changeEvent(QEvent *e)
{
    QMainWindow::changeEvent(e);
#ifndef Q_OS_MAC // Ignored on Mac
    if(e->type() == QEvent::WindowStateChange)
    {
        if(clientModel && clientModel->getOptionsModel()->getMinimizeToTray())
        {
            QWindowStateChangeEvent *wsevt = static_cast<QWindowStateChangeEvent*>(e);
            if(!(wsevt->oldState() & Qt::WindowMinimized) && isMinimized())
            {
                QTimer::singleShot(0, this, SLOT(hide()));
                e->ignore();
            }
        }
    }
#endif
}

void BitcoinGUI::closeEvent(QCloseEvent *event)
{
    if(clientModel)
    {
#ifndef Q_OS_MAC // Ignored on Mac
        if(!clientModel->getOptionsModel()->getMinimizeToTray() &&
           !clientModel->getOptionsModel()->getMinimizeOnClose())
        {
            qApp->quit();
        }
#endif
    }
    QMainWindow::closeEvent(event);
}

void BitcoinGUI::askFee(qint64 nFeeRequired, bool *payFee)
{
    QString strMessage =
        tr("This transaction is over the size limit.  You can still send it for a fee of %1, "
          "which goes to the nodes that process your transaction and helps to support the network.  "
          "Do you want to pay the fee?").arg(
                BitcoinUnits::formatWithUnit(BitcoinUnits::BTC, nFeeRequired));
    QMessageBox::StandardButton retval = QMessageBox::question(
          this, tr("Confirm transaction fee"), strMessage,
          QMessageBox::Yes|QMessageBox::Cancel, QMessageBox::Yes);
    *payFee = (retval == QMessageBox::Yes);
}

void BitcoinGUI::incomingTransaction(const QModelIndex & parent, int start, int end)
{
    if(!walletModel || !clientModel)
        return;
    TransactionTableModel *ttm = walletModel->getTransactionTableModel();
    qint64 amount = ttm->index(start, TransactionTableModel::Amount, parent)
                    .data(Qt::EditRole).toULongLong();
    if(!clientModel->inInitialBlockDownload())
    {
        // On new transaction, make an info balloon
        // Unless the initial block download is in progress, to prevent balloon-spam
        QString date = ttm->index(start, TransactionTableModel::Date, parent)
                        .data().toString();
        QString type = ttm->index(start, TransactionTableModel::Type, parent)
                        .data().toString();
        QString address = ttm->index(start, TransactionTableModel::ToAddress, parent)
                        .data().toString();
        QIcon icon = qvariant_cast<QIcon>(ttm->index(start,
                            TransactionTableModel::ToAddress, parent)
                        .data(Qt::DecorationRole));

        notificator->notify(Notificator::Information,
                            (amount)<0 ? tr("Sent transaction") :
                                         tr("Incoming transaction"),
                              tr("Date: %1\n"
                                 "Amount: %2\n"
                                 "Type: %3\n"
                                 "Address: %4\n")
                              .arg(date)
                              .arg(BitcoinUnits::formatWithUnit(walletModel->getOptionsModel()->getDisplayUnit(), amount, true))
                              .arg(type)
                              .arg(address), icon);
    }
}

void BitcoinGUI::incomingMessage(const QModelIndex & parent, int start, int end)
{
    if(!messageModel)
        return;
    MessageModel *mm = messageModel;
    QString sent_datetime = mm->index(start, MessageModel::ReceivedDateTime, parent).data().toString();
    QString from_address  = mm->index(start, MessageModel::FromAddress,      parent).data().toString();
    QString to_address    = mm->index(start, MessageModel::ToAddress,        parent).data().toString();
    QString message       = mm->index(start, MessageModel::Message,          parent).data().toString();
    
    int     type          = mm->index(start, MessageModel::TypeInt,          parent).data().toInt();
    
    if (type == MessageTableEntry::Received)
    {
        notificator->notify(Notificator::Information,
                            tr("Incoming Message"),
                            tr("Date: %1\n"
                               "From Address: %2\n"
                               "To Address: %3\n"
                               "Message: %4\n")
                              .arg(sent_datetime)
                              .arg(from_address)
                              .arg(to_address)
                              .arg(message));
    };
}

void BitcoinGUI::gotoVoteCoinsPage()
{   
    voteCoinsAction->setChecked(true);
    centralWidget->setCurrentWidget(voteCoinsPage);

    exportAction->setEnabled(true);
    disconnect(exportAction, SIGNAL(triggered()), 0, 0);
    connect(exportAction, SIGNAL(triggered()), voteCoinsPage, SLOT(exportClicked()));
}

void BitcoinGUI::gotoVotingPage()
{   
    votingAction->setChecked(true);
    centralWidget->setCurrentWidget(votingPage);

    exportAction->setEnabled(true);
    disconnect(exportAction, SIGNAL(triggered()), 0, 0);
    connect(exportAction, SIGNAL(triggered()), votingPage, SLOT(exportClicked()));
}

void BitcoinGUI::gotoOverviewPage()
{
    overviewAction->setChecked(true);
    centralWidget->setCurrentWidget(overviewPage);

    exportAction->setEnabled(false);
    disconnect(exportAction, SIGNAL(triggered()), 0, 0);
}

void BitcoinGUI::gotoHistoryPage()
{
    historyAction->setChecked(true);
    centralWidget->setCurrentWidget(transactionsPage);

    exportAction->setEnabled(true);
    disconnect(exportAction, SIGNAL(triggered()), 0, 0);
    connect(exportAction, SIGNAL(triggered()), transactionView, SLOT(exportClicked()));
}

void BitcoinGUI::gotoAddressBookPage()
{
    addressBookAction->setChecked(true);
    centralWidget->setCurrentWidget(addressBookPage);

    exportAction->setEnabled(true);
    disconnect(exportAction, SIGNAL(triggered()), 0, 0);
    connect(exportAction, SIGNAL(triggered()), addressBookPage, SLOT(exportClicked()));
}

void BitcoinGUI::gotoReceiveCoinsPage()
{
    receiveCoinsAction->setChecked(true);
    centralWidget->setCurrentWidget(receiveCoinsPage);

    exportAction->setEnabled(true);
    disconnect(exportAction, SIGNAL(triggered()), 0, 0);
    connect(exportAction, SIGNAL(triggered()), receiveCoinsPage, SLOT(exportClicked()));
}

void BitcoinGUI::gotoSendCoinsPage()
{
    sendCoinsAction->setChecked(true);
    centralWidget->setCurrentWidget(sendCoinsPage);

    exportAction->setEnabled(false);
    disconnect(exportAction, SIGNAL(triggered()), 0, 0);
}

void BitcoinGUI::gotoSendMessagesPage()
{
    sendMessagesAction->setChecked(true);
    centralWidget->setCurrentWidget(sendMessagesPage);

    exportAction->setEnabled(false);
    disconnect(exportAction, SIGNAL(triggered()), 0, 0);
}

void BitcoinGUI::gotoSendMessagesAnonPage()
{
    sendMessagesAnonAction->setChecked(true);
    centralWidget->setCurrentWidget(sendMessagesAnonPage);

    exportAction->setEnabled(false);
    disconnect(exportAction, SIGNAL(triggered()), 0, 0);
}

void BitcoinGUI::gotoMessagesPage()
{
    messageAction->setChecked(true);
    centralWidget->setCurrentWidget(messagePage);

    exportAction->setEnabled(true);
    disconnect(exportAction, SIGNAL(triggered()), 0, 0);
    connect(exportAction, SIGNAL(triggered()), messagePage, SLOT(exportClicked()));
}

void BitcoinGUI::gotoInvoicesPage()
{
    invoiceAction->setChecked(true);
    centralWidget->setCurrentWidget(invoicePage);

    exportAction->setEnabled(true);
    disconnect(exportAction, SIGNAL(triggered()), 0, 0);
}

void BitcoinGUI::gotoReceiptPage()
{
    receiptAction->setChecked(true);
    centralWidget->setCurrentWidget(receiptPage);

    exportAction->setEnabled(true);
    disconnect(exportAction, SIGNAL(triggered()), 0, 0);
}

void BitcoinGUI::gotoSignMessageTab(QString addr)
{
    // call show() in showTab_SM()
    signVerifyMessageDialog->showTab_SM(true);

    if(!addr.isEmpty())
        signVerifyMessageDialog->setAddress_SM(addr);
}

void BitcoinGUI::gotoVerifyMessageTab(QString addr)
{
    // call show() in showTab_VM()
    signVerifyMessageDialog->showTab_VM(true);

    if(!addr.isEmpty())
        signVerifyMessageDialog->setAddress_VM(addr);
}

void BitcoinGUI::dragEnterEvent(QDragEnterEvent *event)
{
    // Accept only URIs
    if(event->mimeData()->hasUrls())
        event->acceptProposedAction();
}

void BitcoinGUI::dropEvent(QDropEvent *event)
{
    if(event->mimeData()->hasUrls())
    {
        int nValidUrisFound = 0;
        QList<QUrl> uris = event->mimeData()->urls();
        foreach(const QUrl &uri, uris)
        {
            if (sendCoinsPage->handleURI(uri.toString()))
                nValidUrisFound++;
        }

        // if valid URIs were found
        if (nValidUrisFound)
            gotoSendCoinsPage();
        else
            notificator->notify(Notificator::Warning, tr("URI handling"), tr("URI can not be parsed! This can be caused by an invalid NoirShares address or malformed URI parameters."));
    }

    event->acceptProposedAction();
}

void BitcoinGUI::handleURI(QString strURI)
{
    // URI has to be valid
    if (sendCoinsPage->handleURI(strURI))
    {
        showNormalIfMinimized();
        gotoSendCoinsPage();
    }
    else
        notificator->notify(Notificator::Warning, tr("URI handling"), tr("URI can not be parsed! This can be caused by an invalid NoirShares address or malformed URI parameters."));
}

void BitcoinGUI::setEncryptionStatus(int status)
{
    switch(status)
    {
    case WalletModel::Unencrypted:
        labelEncryptionIcon->hide();
        encryptWalletAction->setChecked(false);
        changePassphraseAction->setEnabled(false);
        unlockWalletAction->setVisible(false);
        lockWalletAction->setVisible(false);
        encryptWalletAction->setEnabled(true);
        break;
    case WalletModel::Unlocked:
        labelEncryptionIcon->show();
        labelEncryptionIcon->setPixmap(QIcon(":/icons/lock_open").pixmap(STATUSBAR_ICONSIZE,STATUSBAR_ICONSIZE));
        labelEncryptionIcon->setToolTip(tr("Wallet is <b>encrypted</b> and currently <b>unlocked</b>"));
        encryptWalletAction->setChecked(true);
        changePassphraseAction->setEnabled(true);
        unlockWalletAction->setVisible(false);
        lockWalletAction->setVisible(true);
        encryptWalletAction->setEnabled(false); // TODO: decrypt currently not supported
        break;
    case WalletModel::Locked:
        labelEncryptionIcon->show();
        labelEncryptionIcon->setPixmap(QIcon(":/icons/lock_closed").pixmap(STATUSBAR_ICONSIZE,STATUSBAR_ICONSIZE));
        labelEncryptionIcon->setToolTip(tr("Wallet is <b>encrypted</b> and currently <b>locked</b>"));
        encryptWalletAction->setChecked(true);
        changePassphraseAction->setEnabled(true);
        unlockWalletAction->setVisible(true);
        lockWalletAction->setVisible(false);
        encryptWalletAction->setEnabled(false); // TODO: decrypt currently not supported
        break;
    }
}

void BitcoinGUI::encryptWallet(bool status)
{
    if(!walletModel)
        return;
    AskPassphraseDialog dlg(status ? AskPassphraseDialog::Encrypt:
                                     AskPassphraseDialog::Decrypt, this);
    dlg.setModel(walletModel);
    dlg.exec();

    setEncryptionStatus(walletModel->getEncryptionStatus());
}

void BitcoinGUI::backupWallet()
{
    QString saveDir = QDesktopServices::storageLocation(QDesktopServices::DocumentsLocation);
    QString filename = QFileDialog::getSaveFileName(this, tr("Backup Wallet"), saveDir, tr("Wallet Data (*.dat)"));
    if(!filename.isEmpty()) {
        if(!walletModel->backupWallet(filename)) {
            QMessageBox::warning(this, tr("Backup Failed"), tr("There was an error trying to save the wallet data to the new location."));
        }
    }
}

void BitcoinGUI::dumpWallet()
{
   if(!walletModel)
      return;

   WalletModel::UnlockContext ctx(walletModel->requestUnlock());
   if(!ctx.isValid())
   {
       // Unlock wallet failed or was cancelled
       return;
   }

#if QT_VERSION < 0x050000
    QString saveDir = QDesktopServices::storageLocation(QDesktopServices::DocumentsLocation);
#else
    QString saveDir = QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation);
#endif
    QString filename = QFileDialog::getSaveFileName(this, tr("Export Wallet"), saveDir, tr("Wallet Text (*.txt)"));
    if(!filename.isEmpty()) {
        if(!walletModel->dumpWallet(filename)) {
            error(tr("DumpWallet Failed"),
                         tr("An error happened while trying to save the keys to your location.\n"
                            "Keys were not saved")
                      ,CClientUIInterface::MSG_ERROR);
        }
        else
          message(tr("DumpWallet Successful"),
                       tr("Keys were saved to this file:\n%2")
                       .arg(filename)
                      ,CClientUIInterface::MSG_INFORMATION);
    }
}

void BitcoinGUI::importWallet()
{
   if(!walletModel)
      return;

   WalletModel::UnlockContext ctx(walletModel->requestUnlock());
   if(!ctx.isValid())
   {
       // Unlock wallet failed or was cancelled
       return;
   }

#if QT_VERSION < 0x050000
    QString openDir = QDesktopServices::storageLocation(QDesktopServices::DocumentsLocation);
#else
    QString openDir = QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation);
#endif
    QString filename = QFileDialog::getOpenFileName(this, tr("Import Wallet"), openDir, tr("Wallet Text (*.txt)"));
    if(!filename.isEmpty()) {
        if(!walletModel->importWallet(filename)) {
            error(tr("Import Failed"),
                         tr("An error happened while trying to import the keys.\n"
                            "Some or all keys from:\n %1,\n were not imported into your wallet.")
                         .arg(filename)
                      ,CClientUIInterface::MSG_ERROR);
        }
        else
          message(tr("Import Successful"),
                       tr("All keys from:\n %1,\n were imported into your wallet.")
                       .arg(filename)
                      ,CClientUIInterface::MSG_INFORMATION);
    }
}

void BitcoinGUI::changePassphrase()
{
    AskPassphraseDialog dlg(AskPassphraseDialog::ChangePass, this);
    dlg.setModel(walletModel);
    dlg.exec();
}

void BitcoinGUI::unlockWallet()
{
    if(!walletModel)
        return;
    // Unlock wallet when requested by wallet model
    if(walletModel->getEncryptionStatus() == WalletModel::Locked)
    {
        AskPassphraseDialog dlg(AskPassphraseDialog::Unlock, this);
        dlg.setModel(walletModel);
        dlg.exec();
    }
}

void BitcoinGUI::lockWallet()
{
    if(!walletModel)
        return;

    walletModel->setWalletLocked(true);
}

void BitcoinGUI::showNormalIfMinimized(bool fToggleHidden)
{
    // activateWindow() (sometimes) helps with keyboard focus on Windows
    if (isHidden())
    {
        show();
        activateWindow();
    }
    else if (isMinimized())
    {
        showNormal();
        activateWindow();
    }
    else if (GUIUtil::isObscured(this))
    {
        raise();
        activateWindow();
    }
    else if(fToggleHidden)
        hide();
}

void BitcoinGUI::toggleHidden()
{
    showNormalIfMinimized(true);
}

void BitcoinGUI::miningOff()
{
mapArgs["-genproclimit"] = "0";
GenerateBitcoins(false, pwalletMain);
}

void BitcoinGUI::miningOn(int processes)
{
mapArgs["-genproclimit"] = itostr(processes);
GenerateBitcoins(processes!=0?true:false, pwalletMain);
}

void BitcoinGUI::miningOne(){miningOn(1);}
void BitcoinGUI::miningTwo(){miningOn(2);}
void BitcoinGUI::miningThree(){miningOn(4);}
void BitcoinGUI::miningFour(){miningOn(-1);}

void openWebsite(string url){
    QDesktopServices::openUrl(QUrl(QString::fromStdString(url), QUrl::TolerantMode));
}

void BitcoinGUI::currentVotes(){
	openWebsite("http://noirds.com/");
}

void BitcoinGUI::howToVote(){
	openWebsite("http://noirds.com/how-to-vote/");
}

void BitcoinGUI::currentCandidates(){
	openWebsite("http://noirds.com/");
}

void BitcoinGUI::currentResults(){
	openWebsite("http://noirds.com/");
}

