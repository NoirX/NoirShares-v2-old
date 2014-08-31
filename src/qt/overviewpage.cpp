#include "overviewpage.h"
#include "ui_overviewpage.h"

#include "walletmodel.h"
#include "bitcoinunits.h"
#include "optionsmodel.h"
#include "transactiontablemodel.h"
#include "transactionfilterproxy.h"
#include "guiutil.h"
#include "guiconstants.h"
#include "askpassphrasedialog.h"
#include "ircmodel.h"
#include "irc.h"

#include <QAbstractItemDelegate>
#include <QPainter>

#define DECORATION_SIZE 64
#define NUM_ITEMS 6
#define IRC_UPDATE_DELAY 500 // 500ms for now..

class TxViewDelegate : public QAbstractItemDelegate
{
    Q_OBJECT
public:
    TxViewDelegate(): QAbstractItemDelegate(), unit(BitcoinUnits::BTC)
    {

    }

    inline void paint(QPainter *painter, const QStyleOptionViewItem &option,
                      const QModelIndex &index ) const
    {
        painter->save();

        QIcon icon = qvariant_cast<QIcon>(index.data(Qt::DecorationRole));
        QRect mainRect = option.rect;
        QRect decorationRect(mainRect.topLeft(), QSize(DECORATION_SIZE, DECORATION_SIZE));
        int xspace = DECORATION_SIZE + 8;
        int ypad = 6;
        int halfheight = (mainRect.height() - 2*ypad)/2;
        QRect amountRect(mainRect.left() + xspace, mainRect.top()+ypad, mainRect.width() - xspace, halfheight);
        QRect addressRect(mainRect.left() + xspace, mainRect.top()+ypad+halfheight, mainRect.width() - xspace, halfheight);
        icon.paint(painter, decorationRect);

        QDateTime date = index.data(TransactionTableModel::DateRole).toDateTime();
        QString address = index.data(Qt::DisplayRole).toString();
        qint64 amount = index.data(TransactionTableModel::AmountRole).toLongLong();
        bool confirmed = index.data(TransactionTableModel::ConfirmedRole).toBool();
        QVariant value = index.data(Qt::ForegroundRole);
        QColor foreground = option.palette.color(QPalette::Text);
        if(qVariantCanConvert<QColor>(value))
        {
            foreground = qvariant_cast<QColor>(value);
        }

        painter->setPen(foreground);
        painter->drawText(addressRect, Qt::AlignLeft|Qt::AlignVCenter, address);

        if(amount < 0)
        {
            foreground = COLOR_NEGATIVE;
        }
        else if(!confirmed)
        {
            foreground = COLOR_UNCONFIRMED;
        }
        else
        {
            foreground = option.palette.color(QPalette::Text);
        }
        painter->setPen(foreground);
        QString amountText = BitcoinUnits::formatWithUnit(unit, amount, true);
        if(!confirmed)
        {
            amountText = QString("[") + amountText + QString("]");
        }
        painter->drawText(amountRect, Qt::AlignRight|Qt::AlignVCenter, amountText);

        painter->setPen(option.palette.color(QPalette::Text));
        painter->drawText(amountRect, Qt::AlignLeft|Qt::AlignVCenter, GUIUtil::dateTimeStr(date));

        painter->restore();
    }

    inline QSize sizeHint(const QStyleOptionViewItem &option, const QModelIndex &index) const
    {
        return QSize(DECORATION_SIZE, DECORATION_SIZE);
    }

    int unit;

};
#include "overviewpage.moc"

OverviewPage::OverviewPage(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::OverviewPage),
    currentBalanceTotal(-1),
    currentBalanceWatchOnly(0),
    currentStake(0),
    currentUnconfirmedBalance(-1),
    currentImmatureBalance(-1),
    txdelegate(new TxViewDelegate()),
    filter(0)
{
    ui->setupUi(this);

    // Recent transactions
    ui->listTransactions->setItemDelegate(txdelegate);
    ui->listTransactions->setIconSize(QSize(DECORATION_SIZE, DECORATION_SIZE));
    ui->listTransactions->setMinimumHeight(NUM_ITEMS * (DECORATION_SIZE + 2));
    ui->listTransactions->setAttribute(Qt::WA_MacShowFocusRect, false);

    connect(ui->listTransactions, SIGNAL(clicked(QModelIndex)), this, SLOT(handleTransactionClicked(QModelIndex)));
    connect(ui->lineEditTrollBox, SIGNAL(returnPressed()),this, SLOT(sendIRCMessage()));

    // init "out of sync" warning labels
    ui->labelWalletStatus->setText("(" + tr("out of sync") + ")");
    ui->labelTransactionsStatus->setText("(" + tr("out of sync") + ")");

    // start with displaying the "out of sync" warnings
    showOutOfSyncWarning(true);
}

void OverviewPage::handleTransactionClicked(const QModelIndex &index)
{
    if(filter)
        emit transactionClicked(filter->mapToSource(index));
}

void OverviewPage::sendIRCMessage()
{
    QString text = ui->lineEditTrollBox->text();

    Send(text.toStdString());

    ui->lineEditTrollBox->clear();

    QTime now;
    QString append = "[" + now.currentTime().toString() + "] <" + ircmodel->getOptionsModel()->getTrollName() + "> " + text; // TODO: Get IRC Nick

    ui->trollBox->append(append);
}

OverviewPage::~OverviewPage()
{
    delete ui;
}

void OverviewPage::setBalance(qint64 total, qint64 watchOnly, qint64 stake, qint64 unconfirmedBalance, qint64 immatureBalance)
{
    int unit = model->getOptionsModel()->getDisplayUnit();
    currentBalanceTotal = total;
    currentBalanceWatchOnly = watchOnly;
    currentStake = stake;
    currentUnconfirmedBalance = unconfirmedBalance;
    currentImmatureBalance = immatureBalance;
    ui->labelBalanceTotal->setText(BitcoinUnits::formatWithUnit(unit, total));
    ui->labelBalanceWatchOnly->setText(BitcoinUnits::formatWithUnit(unit, watchOnly));
    ui->labelStake->setText(BitcoinUnits::formatWithUnit(unit, stake));
    ui->labelUnconfirmed->setText(BitcoinUnits::formatWithUnit(unit, unconfirmedBalance));
    ui->labelImmature->setText(BitcoinUnits::formatWithUnit(unit, immatureBalance));

    // only show immature (newly mined) balance if it's non-zero, so as not to complicate things
    // for the non-mining users
    bool showImmature = immatureBalance != 0;
    ui->labelImmature->setVisible(showImmature);
    ui->labelImmatureText->setVisible(showImmature);

    // only show watch-only balance if it's non-zero, so as not to complicate things
    // for users
    bool showWatchOnly = watchOnly != 0;
    ui->labelBalanceWatchOnly->setVisible(showWatchOnly);
    ui->labelBalanceWatchOnlyText->setVisible(showWatchOnly);
}

void OverviewPage::ircAppendMessage(QString message)
{
    QStringList messageparts = message.split(" ");

    if(messageparts.at(1) == "315")
    {
        ui->trollBox->setPlainText("Connected to IRC\n");
        ui->lineEditTrollBox->setEnabled(true);
        updateTrollName();
    }

    if(messageparts.at(1) != "PRIVMSG")
        return;

    QTime now;

    QString from = messageparts.at(0);
    QString channel = messageparts.at(2);

    channel = (channel.indexOf("#") == -1 ? "private : " : "");

    from = from.remove(0, 1);
    from = from.remove(from.indexOf("!"), from.length());
    QString text = "[" + now.currentTime().toString() + "] <" + channel + from + ">";

    for (int i = 3; i < messageparts.size(); ++i)
        text += " " + (i == 3 ? QString(messageparts.at(3)).remove(0, 1) : messageparts.at(i));

    ui->trollBox->append(text);
}

void OverviewPage::setNumTransactions(int count)
{
    ui->labelNumTransactions->setText(QLocale::system().toString(count));
}

void OverviewPage::unlockWallet()
{
    if(model->getEncryptionStatus() == WalletModel::Locked)
    {
        AskPassphraseDialog dlg(AskPassphraseDialog::Unlock, this);
        dlg.setModel(model);
        if(dlg.exec() == QDialog::Accepted)
        {
            ui->unlockWalletButton->setText(QString("Lock Wallet"));
        }
    }
    else
    {
        model->setWalletLocked(true);
        ui->unlockWalletButton->setText(QString("Unlock Wallet"));
    }
}

void OverviewPage::setModel(WalletModel *model)
{
    this->model = model;
    if(model && model->getOptionsModel())
    {
        // Set up transaction list
        filter = new TransactionFilterProxy();
        filter->setSourceModel(model->getTransactionTableModel());
        filter->setLimit(NUM_ITEMS);
        filter->setDynamicSortFilter(true);
        filter->setSortRole(Qt::EditRole);
        filter->sort(TransactionTableModel::Status, Qt::DescendingOrder);

        ui->listTransactions->setModel(filter);
        ui->listTransactions->setModelColumn(TransactionTableModel::ToAddress);

        // Keep up to date with wallet
        setBalance(model->getBalance(), model->getBalanceWatchOnly(), model->getStake(), model->getUnconfirmedBalance(), model->getImmatureBalance());
        connect(model, SIGNAL(balanceChanged(qint64, qint64, qint64, qint64, qint64)), this, SLOT(setBalance(qint64, qint64, qint64, qint64, qint64)));

        setNumTransactions(model->getNumTransactions());
        connect(model, SIGNAL(numTransactionsChanged(int)), this, SLOT(setNumTransactions(int)));

        connect(model->getOptionsModel(), SIGNAL(displayUnitChanged(int)), this, SLOT(updateDisplayUnit()));

        // Unlock wallet button
        WalletModel::EncryptionStatus status = model->getEncryptionStatus();
        if(status == WalletModel::Unencrypted)
        {
            ui->unlockWalletButton->setDisabled(true);
        }
        connect(ui->unlockWalletButton, SIGNAL(clicked()), this, SLOT(unlockWallet()));
     }

    // update the display unit, to not use the default ("ECC")
    updateDisplayUnit();
}

void OverviewPage::setIRCModel(IRCModel *ircmodel)
{
    this->ircmodel = ircmodel;

    if(ircmodel)
    {
        // Get IRC Messages
        connect(ircmodel->getOptionsModel(), SIGNAL(enableTrollboxChanged(bool)), this, SLOT(enableTrollbox()));
        connect(ircmodel->getOptionsModel(), SIGNAL(trollNameChanged(QString)), this, SLOT(updateTrollName()));

        enableTrollbox();
    }
}

void OverviewPage::enableTrollbox()
{
    if(ircmodel && ircmodel->getOptionsModel())
    {
        bool enableTrollbox = ircmodel->getOptionsModel()->getEnableTrollbox();

        if(enableTrollbox)
        {
            disconnect(ircmodel, SIGNAL(ircMessageReceived(QString)), this, SLOT(ircAppendMessage(QString)));
               connect(ircmodel, SIGNAL(ircMessageReceived(QString)), this, SLOT(ircAppendMessage(QString)));
            ui->trollBox->setPlainText(QString::fromLocal8Bit(ircmodel->getIRCConnected() ? "Connected" : "Connecting") + " to IRC\n");
            ui->trollBox->setEnabled(true);
            ui->lineEditTrollBox->setEnabled(true);
        }
        else
        {
            disconnect(ircmodel, SIGNAL(ircMessageReceived(QString)), this, SLOT(ircAppendMessage(QString)));
            ui->trollBox->setEnabled(false);
            ui->lineEditTrollBox->setEnabled(false);
        }
    }
}

void OverviewPage::updateTrollName()
{
    if(ircmodel && ircmodel->getOptionsModel())
    {
        QString trollname = "/nick " + ircmodel->getOptionsModel()->getTrollName();

        Send(trollname.toStdString());
    }
}

void OverviewPage::updateDisplayUnit()
{
    if(model && model->getOptionsModel())
    {
        if(currentBalanceTotal != -1)
            setBalance(currentBalanceTotal, currentBalanceWatchOnly, model->getStake(), currentUnconfirmedBalance, currentImmatureBalance);

        // Update txdelegate->unit with the current unit
        txdelegate->unit = model->getOptionsModel()->getDisplayUnit();

        ui->listTransactions->update();
    }
}

void OverviewPage::showOutOfSyncWarning(bool fShow)
{
    ui->labelWalletStatus->setVisible(fShow);
    ui->labelTransactionsStatus->setVisible(fShow);
}