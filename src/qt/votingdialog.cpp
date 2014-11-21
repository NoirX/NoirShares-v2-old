// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
// Copyright (c) 2013-2014 Memorycoin Dev Team

#include "votingdialog.h"
#include "ui_votingdialog.h"

#include "walletmodel.h"
#include "bitcoinunits.h"
#include "addressbookpage.h"
#include "optionsmodel.h"
#include "votingentry.h"
#include "guiutil.h"
#include "askpassphrasedialog.h"
#include "base58.h"

#include <QMessageBox>
#include <QTextDocument>
#include <QScrollBar>

VotingDialog::VotingDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::VotingDialog),
    model(0)
{
    ui->setupUi(this);
#ifdef Q_OS_MAC // Icons on push buttons are very uncommon on Mac
    ui->addButton->setIcon(QIcon());
    ui->clearButton->setIcon(QIcon());
    ui->sendButton->setIcon(QIcon());
#endif

    addEntry();

    connect(ui->addButton, SIGNAL(clicked()), this, SLOT(addEntry()));
    connect(ui->clearButton, SIGNAL(clicked()), this, SLOT(clear()));

    fNewRecipientAllowed = true;
}

void VotingDialog::setModel(WalletModel *model)
{
    this->model = model;

    for(int i = 0; i < ui->entries->count(); ++i)
    {
        VotingEntry *entry = qobject_cast<VotingEntry*>(ui->entries->itemAt(i)->widget());
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


VotingDialog::~VotingDialog()
{
    delete ui;
}

void VotingDialog::sendToRecipients(){

    QList<SendCoinsRecipient> recipients;

    {
        bool valid = true;

        if(!model)
            return;

        for(int i = 0; i < ui->entries->count(); ++i)
        {
            VotingEntry *entry = qobject_cast<VotingEntry*>(ui->entries->itemAt(i)->widget());
            if(entry)
            {
                if(entry->validate())
                {
                    recipients.append(entry->getValue());
                }
                else
                {
                    valid = false;
                }
            }
        }

        if(!valid || recipients.isEmpty())
        {
            return;
        }
    }

    // Format confirmation message
    QStringList formatted;
    foreach(const SendCoinsRecipient &rcp, recipients)
    {
     #if QT_VERSION >= 0x050000
        formatted.append(tr("<b>%1</b> to %2 (%3)").arg(BitcoinUnits::formatWithUnit(BitcoinUnits::NRS, rcp.amount), rcp.label.toHtmlEscaped(), rcp.address));
     #else
        formatted.append(tr("<b>%1</b> to %2 (%3)").arg(BitcoinUnits::formatWithUnit(BitcoinUnits::NRS, rcp.amount), Qt::escape(rcp.label), rcp.address));
     #endif
    }

    fNewRecipientAllowed = false;

    
    WalletModel::UnlockContext ctx(model->requestUnlock());
    if(!ctx.isValid())
    {
        // Unlock wallet was cancelled
        fNewRecipientAllowed = true;
        return;
    }

    WalletModel::SendCoinsReturn sendstatus = model->sendCoins(recipients);
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
    case WalletModel::AmountWithFeeExceedsBalance:
        QMessageBox::warning(this, tr("Send Coins"),
            tr("The total exceeds your balance when the %1 transaction fee is included.").
            arg(BitcoinUnits::formatWithUnit(BitcoinUnits::NRS, sendstatus.fee)),
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

void VotingDialog::on_sendButton_clicked()
{
    sendToRecipients();
}

void VotingDialog::clear()
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

void VotingDialog::reject()
{
    clear();
}

void VotingDialog::accept()
{
    clear();
}

VotingEntry *VotingDialog::addEntry()
{
    VotingEntry *entry = new VotingEntry(this);
    entry->setModel(model);
    ui->entries->addWidget(entry);
    connect(entry, SIGNAL(removeEntry(VotingEntry*)), this, SLOT(removeEntry(VotingEntry*)));

    updateRemoveEnabled();

    // Focus the field, so that entry can start immediately
    entry->clear();
    entry->setFocus();
    //ui->scrollAreaWidgetContents->resize(ui->scrollAreaWidgetContents->sizeHint());
    qApp->processEvents();
    //QScrollBar* bar = ui->scrollArea->verticalScrollBar();
    //if(bar)
    //    bar->setSliderPosition(bar->maximum());
    return entry;
}

void VotingDialog::updateRemoveEnabled()
{
    // Remove buttons are enabled as soon as there is more than one send-entry
    bool enabled = (ui->entries->count() > 1);
    for(int i = 0; i < ui->entries->count(); ++i)
    {
        VotingEntry *entry = qobject_cast<VotingEntry*>(ui->entries->itemAt(i)->widget());
        if(entry)
        {
            entry->setRemoveEnabled(enabled);
        }
    }
    //setupTabChain(0);
}

void VotingDialog::removeEntry(VotingEntry* entry)
{
    delete entry;
    updateRemoveEnabled();
}

void VotingDialog::setAddress(const QString &address)
{
    VotingEntry *entry = 0;
    // Replace the first entry if it is still unused
    if(ui->entries->count() == 1)
    {
        VotingEntry *first = qobject_cast<VotingEntry*>(ui->entries->itemAt(0)->widget());
        if(first->isClear())
        {
            entry = first;
        }
    }
    if(!entry)
    {
        entry = addEntry();
    }

    entry->setAddress(address);
}

void VotingDialog::pasteEntry(const SendCoinsRecipient &rv)
{
    if(!fNewRecipientAllowed)
        return;

    VotingEntry *entry = 0;
    // Replace the first entry if it is still unused
    if(ui->entries->count() == 1)
    {
        VotingEntry *first = qobject_cast<VotingEntry*>(ui->entries->itemAt(0)->widget());
        if(first->isClear())
        {
            entry = first;
        }
    }
    if(!entry)
    {
        entry = addEntry();
    }

    entry->setValue(rv);
}


