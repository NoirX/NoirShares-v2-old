// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
// Copyright (c) 2013-2014 Memorycoin Dev Team

#include "votingentry.h"
#include "ui_votingentry.h"

#include "guiutil.h"
#include "bitcoinunits.h"
#include "addressbookpage.h"
#include "walletmodel.h"
#include "optionsmodel.h"
#include "addresstablemodel.h"


#include <QApplication>
#include <QClipboard>

VotingEntry::VotingEntry(QWidget *parent) :
    QFrame(parent),
    ui(new Ui::VotingEntry),
    model(0)
{
    ui->setupUi(this);

#ifdef Q_OS_MAC
    ui->payToLayout->setSpacing(4);
#endif
#if QT_VERSION >= 0x040700
    /* Do not move this to the XML file, Qt before 4.7 will choke on it */
    //ui->addAsLabel->setPlaceholderText(tr("Enter a label for this address to add it to your address book"));
    ui->payTo->setPlaceholderText(tr("Enter voting address -starts with NRS"));
#endif
    setFocusPolicy(Qt::TabFocus);
    setFocusProxy(ui->payTo);

    GUIUtil::setupAddressWidget(ui->payTo, this);
}

VotingEntry::~VotingEntry()
{
    delete ui;
}

void VotingEntry::on_pasteButton_clicked()
{
    // Paste text from clipboard into recipient field
    ui->payTo->setText(QApplication::clipboard()->text());
}

void VotingEntry::on_addressBookButton_clicked()
{
    if(!model)
        return;
    AddressBookPage dlg(AddressBookPage::ForSending, AddressBookPage::SendingTab, this);
    dlg.setModel(model->getAddressTableModel());
    if(dlg.exec())
    {
        ui->payTo->setText(dlg.getReturnValue());
        //ui->payAmount->setFocus();
    }
}

void VotingEntry::on_payTo_textChanged(const QString &address)
{
    if(!model)
        return;
    // Fill in label from address book, if address has an associated label
    QString associatedLabel = model->getAddressTableModel()->labelForAddress(address);
    //if(!associatedLabel.isEmpty())
    //    ui->addAsLabel->setText(associatedLabel);
}

void VotingEntry::setModel(WalletModel *model)
{
    this->model = model;

    if(model && model->getOptionsModel())
        connect(model->getOptionsModel(), SIGNAL(displayUnitChanged(int)), this, SLOT(updateDisplayUnit()));

    clear();
}

void VotingEntry::setRemoveEnabled(bool enabled)
{
    ui->deleteButton->setEnabled(enabled);
}

void VotingEntry::clear()
{
    ui->payTo->clear();
    //ui->addAsLabel->clear();
    //ui->payAmount->clear();
    ui->payTo->setFocus();
    // update the display unit, to not use the default ("NRS")
    updateDisplayUnit();
}

void VotingEntry::on_deleteButton_clicked()
{
    emit removeEntry(this);
}

bool VotingEntry::validate()
{
    // Check input validity
    bool retval = true;

    /*if(!ui->payAmount->validate())
    {
        retval = false;
    }
    else
    {
        if(ui->payAmount->value() <= 0)
        {
            // Cannot send 0 coins or less
            ui->payAmount->setValid(false);
            retval = false;
        }
    }*/

    if(!ui->payTo->hasAcceptableInput() ||
       (model && !model->validateAddress(ui->payTo->text())))
    {
        ui->payTo->setValid(false);
        retval = false;
    }

    if(!ui->payTo->text().startsWith("NRS")){
        ui->payTo->setValid(false);
        retval = false;
    }

    return retval;
}

SendCoinsRecipient VotingEntry::getValue()
{
    SendCoinsRecipient rv;

    rv.address = ui->payTo->text();
    //rv.label = ui->addAsLabel->text();
    rv.amount =  ui->payAmount->currentIndex()+1;
            //itemData();
            //value();

    return rv;
}

void VotingEntry::setValue(const SendCoinsRecipient &value)
{
    ui->payTo->setText(value.address);
    
}

void VotingEntry::setAddress(const QString &address)
{
    ui->payTo->setText(address);
    
}

bool VotingEntry::isClear()
{
    return ui->payTo->text().isEmpty();
}

void VotingEntry::setFocus()
{
    ui->payTo->setFocus();
}

void VotingEntry::updateDisplayUnit()
{
    if(model && model->getOptionsModel())
    {
        
    }
}
