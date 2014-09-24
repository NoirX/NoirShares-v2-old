#include "votecoinsdialog.h"
#include "ui_votecoinsdialog.h"

#include "walletmodel.h"
#include "bitcoinunits.h"
#include "addressbookpage.h"
#include "optionsmodel.h"
#include "votecoinsentry.h"
#include "guiutil.h"
#include "askpassphrasedialog.h"
#include "base58.h"


#include <QMessageBox>
#include <QTextDocument>
#include <QScrollBar>

VoteCoinsDialog::VoteCoinsDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::VoteCoinsDialog),
    model(0)
{
    ui->setupUi(this);
#ifdef Q_OS_MAC // Icons on push buttons are very uncommon on Mac
    ui->clearButton->setIcon(QIcon());
    ui->sendButton->setIcon(QIcon());
#endif

    addEntry();

    //connect(ui->addButton, SIGNAL(clicked()), this, SLOT(addEntry()));
    connect(ui->clearButton, SIGNAL(clicked()), this, SLOT(clear()));

    fNewRecipientAllowed = true;
}

void VoteCoinsDialog::setModel(WalletModel *model)
{
    this->model = model;

    for(int i = 0; i < ui->entries->count(); ++i)
    {
        VoteCoinsEntry *entry = qobject_cast<VoteCoinsEntry*>(ui->entries->itemAt(i)->widget());
        if(entry)
        {
            entry->setModel(model);
        }
    }
    if(model && model->getOptionsModel())
    {
        //setBalance(model->getBalance(), model->getUnconfirmedBalance(), model->getImmatureBalance());
        //connect(model, SIGNAL(balanceChanged(qint64, qint64, qint64)), this, SLOT(setBalance(qint64, qint64, qint64)));
        //connect(model->getOptionsModel(), SIGNAL(displayUnitChanged(int)), this, SLOT(updateDisplayUnit()));
    }
}


VoteCoinsDialog::~VoteCoinsDialog()
{
    delete ui;
}

void VoteCoinsDialog::sendToRecipients(){

    QList<SendCoinsRecipient> recipients;

    bool valid = true;
    int64 totalPlay=0;

    if(!model)
        return;

        VoteCoinsEntry *entry = qobject_cast<VoteCoinsEntry*>(ui->entries->itemAt(0)->widget());
        if(entry){
            if(entry->getGameType()==0){
                //Lottery
                if(entry->validate()){
                    for(int i=0;i<7;i++){
                        recipients.append(entry->getValue(i));
                        totalPlay+=recipients[i].amount;
                    }
                }
                else{
                    valid = false;
                }
            }
        }


        if(!valid || recipients.isEmpty())
        {
            return;
        }

    
    fNewRecipientAllowed = false;

    QMessageBox::StandardButton retval = QMessageBox::question(this, tr("Confirm ticket"),
                          tr("Are you sure you want to play the amount %1 for this ticket?").arg(BitcoinUnits::formatWithUnit(BitcoinUnits::BTC, totalPlay)),
          QMessageBox::Yes|QMessageBox::Cancel,
          QMessageBox::Cancel);

    if(retval != QMessageBox::Yes)
    {
        fNewRecipientAllowed = true;
        return;
    }

    WalletModel::UnlockContext ctx(model->requestUnlock());
    if(!ctx.isValid())
    {
        // Unlock wallet was cancelled
        fNewRecipientAllowed = true;
        return;
    }

    WalletModel::SendCoinsReturn sendstatus;

    if(entry->getGameType()==0){
        sendstatus= model->sendCoins(recipients, NULL, true);
        if(sendstatus.status==WalletModel::SatoshiForChangeAddressRequired){
            //try again
            if(recipients[6].amount>2){
                recipients[6].amount=recipients[6].amount-1;
                sendstatus = model->sendCoins(recipients, NULL, true);
            }
        }
    }
    switch(sendstatus.status)
    {
    case WalletModel::InvalidAddress:
        QMessageBox::warning(this, tr("Send Coins"),
            tr("The recipient address is not valid, please recheck."),
            QMessageBox::Ok, QMessageBox::Ok);
        break;
    case WalletModel::InvalidAmount:
        QMessageBox::warning(this, tr("Send Coins"),
            tr("The amount to pay must be larger than 0."),
            QMessageBox::Ok, QMessageBox::Ok);
        break;
    case WalletModel::AmountExceedsBalance:
        QMessageBox::warning(this, tr("Send Coins"),
            tr("The amount exceeds your balance."),
            QMessageBox::Ok, QMessageBox::Ok);
        break;

    case WalletModel::SatoshiForChangeAddressRequired:
        QMessageBox::warning(this, tr("Send Coins"),
            tr("This exact amount cannot be played from your wallet at this time (for boring technical reasons). Try changing the amount to 1 satoshi more or less."),
            QMessageBox::Ok, QMessageBox::Ok);
        break;


    case WalletModel::AmountWithFeeExceedsBalance:
        
        QMessageBox::warning(this, tr("Send Coins"),
            tr("The total exceeds your balance when the %1 transaction fee is included.").
            arg(BitcoinUnits::formatWithUnit(BitcoinUnits::BTC, sendstatus.fee)),
            QMessageBox::Ok, QMessageBox::Ok);
        break;
    case WalletModel::DuplicateAddress:
        QMessageBox::warning(this, tr("Send Coins"),
            tr("Duplicate address found, can only send to each address once per send operation."),
            QMessageBox::Ok, QMessageBox::Ok);
        break;
    case WalletModel::TransactionCreationFailed:
        QMessageBox::warning(this, tr("Send Coins"),
            tr("Error: Transaction creation failed!"),
            QMessageBox::Ok, QMessageBox::Ok);
        break;
    case WalletModel::TransactionCommitFailed:
        QMessageBox::warning(this, tr("Send Coins"),
            tr("Error: The transaction was rejected. This might happen if some of the coins in your wallet were already spent, such as if you used a copy of wallet.dat and coins were spent in the copy but not marked as spent here."),
            QMessageBox::Ok, QMessageBox::Ok);
        break;
    case WalletModel::Aborted: // User aborted, nothing to do
        break;
    case WalletModel::OK:
        accept();
        break;
    }
    fNewRecipientAllowed = true;
}

void VoteCoinsDialog::on_sendButton_clicked()
{
    sendToRecipients();
}

void VoteCoinsDialog::clear()
{
    // Remove entries until only one left
    while(ui->entries->count())
    {
        delete ui->entries->takeAt(0)->widget();
    }
    addEntry();

    updateRemoveEnabled();

    ui->sendButton->setDefault(true);
}

void VoteCoinsDialog::reject()
{
    clear();
}

void VoteCoinsDialog::accept()
{
    clear();
}

VoteCoinsEntry *VoteCoinsDialog::addEntry()
{
    VoteCoinsEntry *entry = new VoteCoinsEntry(this);
    entry->setModel(model);
    ui->entries->addWidget(entry);
    connect(entry, SIGNAL(removeEntry(VoteCoinsEntry*)), this, SLOT(removeEntry(VoteCoinsEntry*)));

    updateRemoveEnabled();

    // Focus the field, so that entry can start immediately
    //entry->clear();
    entry->setFocus();
    //ui->scrollAreaWidgetContents->resize(ui->scrollAreaWidgetContents->sizeHint());
    qApp->processEvents();
    //QScrollBar* bar = ui->scrollArea->verticalScrollBar();
    //if(bar)
    //    bar->setSliderPosition(bar->maximum());
    return entry;
}

void VoteCoinsDialog::updateRemoveEnabled()
{
    // Remove buttons are enabled as soon as there is more than one send-entry
    bool enabled = (ui->entries->count() > 1);
    for(int i = 0; i < ui->entries->count(); ++i)
    {
        VoteCoinsEntry *entry = qobject_cast<VoteCoinsEntry*>(ui->entries->itemAt(i)->widget());
        if(entry)
        {
            //entry->setRemoveEnabled(enabled);
        }
    }
    //setupTabChain(0);
}

void VoteCoinsDialog::removeEntry(VoteCoinsEntry* entry)
{
    delete entry;
    updateRemoveEnabled();
}

/*QWidget *VoteCoinsDialog::setupTabChain(QWidget *prev)
{
    for(int i = 0; i < ui->entries->count(); ++i)
    {
        VoteCoinsEntry *entry = qobject_cast<VoteCoinsEntry*>(ui->entries->itemAt(i)->widget());
        if(entry)
        {
            prev = entry->setupTabChain(prev);
        }
    }
    QWidget::setTabOrder(prev, ui->addButton);
    QWidget::setTabOrder(ui->addButton, ui->sendButton);
    return ui->sendButton;
}*/

void VoteCoinsDialog::setAddress(const QString &address)
{
    VoteCoinsEntry *entry = 0;
    // Replace the first entry if it is still unused
    if(ui->entries->count() == 1)
    {
        VoteCoinsEntry *first = qobject_cast<VoteCoinsEntry*>(ui->entries->itemAt(0)->widget());
        /*if(first->isClear())
        {
            entry = first;
        }*/
    }
    if(!entry)
    {
        entry = addEntry();
    }

    entry->setAddress(address);
}

void VoteCoinsDialog::pasteEntry(const SendCoinsRecipient &rv)
{
    if(!fNewRecipientAllowed)
        return;

    VoteCoinsEntry *entry = 0;
    // Replace the first entry if it is still unused
    if(ui->entries->count() == 1)
    {
        VoteCoinsEntry *first = qobject_cast<VoteCoinsEntry*>(ui->entries->itemAt(0)->widget());
        /*if(first->isClear())
        {
            entry = first;
        }*/
    }
    if(!entry)
    {
        entry = addEntry();
    }

    entry->setValue(rv);
}

/*bool VoteCoinsDialog::handleURI(const QString &uri)
{
    SendCoinsRecipient rv;
    // URI has to be valid
    if (GUIUtil::parseBitcoinURI(uri, &rv))
    {
        CBitcoinAddress address(rv.address.toStdString());
        if (!address.IsValid())
            return false;
        pasteEntry(rv);
        return true;
    }

    return false;
}*/

/*void VoteCoinsDialog::setBalance(qint64 balance, qint64 unconfirmedBalance, qint64 immatureBalance)
{
    Q_UNUSED(unconfirmedBalance);
    Q_UNUSED(immatureBalance);
    if(!model || !model->getOptionsModel())
        return;

    int unit = model->getOptionsModel()->getDisplayUnit();
    ui->labelBalance->setText(BitcoinUnits::formatWithUnit(unit, balance));
}

void VoteCoinsDialog::updateDisplayUnit()
{
    if(model && model->getOptionsModel())
    {
        // Update labelBalance with the current balance and the current unit
        ui->labelBalance->setText(BitcoinUnits::formatWithUnit(model->getOptionsModel()->getDisplayUnit(), model->getBalance()));
    }
}*/
