#include "votecoinsentry.h"
#include "ui_votecoinsentry.h"

#include "guiutil.h"
#include "bitcoinunits.h"
#include "addressbookpage.h"
#include "walletmodel.h"
#include "optionsmodel.h"
#include "addresstablemodel.h"
#include <set>


#include <QApplication>
#include <QClipboard>

VoteCoinsEntry::VoteCoinsEntry(QWidget *parent) :
    QFrame(parent),
    ui(new Ui::VoteCoinsEntry),
    model(0)
{
    ui->setupUi(this);

#if QT_VERSION >= 0x040700
    /* Do not move this to the XML file, Qt before 4.7 will choke on it */
    //ui->addAsLabel->setPlaceholderText(tr("Enter a label for this address to add it to your address book"));
    //ui->payAmount->setPlaceholderText(tr("Amount to play"));
#endif
    setFocusPolicy(Qt::TabFocus);
    setFocusProxy(ui->payAmount);
    this->on_QuickPick_clicked();
    ui->payAmount->setValue(1000000);
    

    //GUIUtil::setupAddressWidget(ui->payTo, this);
}

VoteCoinsEntry::~VoteCoinsEntry()
{
    delete ui;
}

/*
void VoteCoinsEntry::on_pasteButton_clicked()
{
    // Paste text from clipboard into recipient field
    ui->payTo->setText(QApplication::clipboard()->text());
}

void VoteCoinsEntry::on_addressBookButton_clicked()
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

void VoteCoinsEntry::on_payTo_textChanged(const QString &address)
{
    if(!model)
        return;
    // Fill in label from address book, if address has an associated label
    QString associatedLabel = model->getAddressTableModel()->labelForAddress(address);
    //if(!associatedLabel.isEmpty())
    //    ui->addAsLabel->setText(associatedLabel);
}
*/
void VoteCoinsEntry::setModel(WalletModel *model)
{
    this->model = model;

    if(model && model->getOptionsModel())
        connect(model->getOptionsModel(), SIGNAL(displayUnitChanged(int)), this, SLOT(updateDisplayUnit()));

    //clear();
}

void VoteCoinsEntry::setRemoveEnabled(bool enabled)
{
    //ui->deleteButton->setEnabled(enabled);
}


void VoteCoinsEntry::clear()
{
    //ui->payTo->clear();
    //ui->addAsLabel->clear();
    //ui->payAmount->clear();
    //ui->payTo->setFocus();
    // update the display unit, to not use the default ("BTC")
    //updateDisplayUnit();
}

void VoteCoinsEntry::on_deleteButton_clicked()
{
    //emit removeEntry(this);
}

bool VoteCoinsEntry::validate()
{
    // Check input validity
    bool retval = true;


    //Amount larget than minimum amount

    //Six numbers chosen

    //Numbers are all different


    if(!ui->payAmount->validate())
    {
        retval = false;
    }
    else
    {
        if(ui->payAmount->value() < 1000)
        {
            // Cannot play less than 1000
            ui->payAmount->setValid(false);
            retval = false;
        }
    }

    std::set<int> myset;
    myset.insert(ui->number1->currentIndex());
    myset.insert(ui->number1_2->currentIndex());
    myset.insert(ui->number1_3->currentIndex());
    myset.insert(ui->number1_4->currentIndex());
    myset.insert(ui->number1_5->currentIndex());
    myset.insert(ui->number1_6->currentIndex());

    if(myset.size()<6){
        retval=false;
    }

    return retval;
}

int VoteCoinsEntry::getGameType(){
    return ui->gamePanel->currentIndex();
}



SendCoinsRecipient VoteCoinsEntry::getValue(int ballNumber)
{
    SendCoinsRecipient rv;
    rv.address = "NbUs6cqeo8CiUfAyz7yaRc3WWiFUK58F3Q";
    rv.label = "Lottery Ticket";
    int totalBallCost=0;
    switch (ballNumber){
    case 0:
        rv.amount =  ui->number1->currentIndex()+1;
        break;
    case 1:
        rv.amount =  ui->number1_2->currentIndex()+1;
        break;
    case 2:
        rv.amount =  ui->number1_3->currentIndex()+1;
        break;
    case 3:
        rv.amount =  ui->number1_4->currentIndex()+1;
        break;
    case 4:
        rv.amount =  ui->number1_5->currentIndex()+1;
        break;
    case 5:
        rv.amount =  ui->number1_6->currentIndex()+1;
        break;
    case 6:
        totalBallCost=ui->number1->currentIndex()+
                ui->number1_2->currentIndex()+
                ui->number1_3->currentIndex()+
                ui->number1_4->currentIndex()+
                ui->number1_5->currentIndex()+
                ui->number1_6->currentIndex()+
                6;
        rv.amount=ui->payAmount->value()-totalBallCost;
        break;

    }
    return rv;
}



/*QWidget *VoteCoinsEntry::setupTabChain(QWidget *prev)
{
    QWidget::setTabOrder(prev, ui->payTo);
    QWidget::setTabOrder(ui->payTo, ui->addressBookButton);
    QWidget::setTabOrder(ui->addressBookButton, ui->pasteButton);
    QWidget::setTabOrder(ui->pasteButton, ui->deleteButton);
    //QWidget::setTabOrder(ui->deleteButton, ui->addAsLabel);
    //return ui->payAmount->setupTabChain(ui->addAsLabel);
    //return ui->deleteButton->setupTabChain(ui->deleteButton);
    return NULL;
}*/

void VoteCoinsEntry::setValue(const SendCoinsRecipient &value)
{
    //ui->payTo->setText(value.address);
    //ui->addAsLabel->setText(value.label);
    //ui->payAmount->setValue(value.amount);
}

void VoteCoinsEntry::setAddress(const QString &address)
{
    //ui->payTo->setText(address);
    //ui->payAmount->setFocus();
}

/*bool VoteCoinsEntry::isClear()
{
    return ui->payAmount->text().isEmpty();
}*/

void VoteCoinsEntry::setFocus()
{
    //ui->payTo->setFocus();
}

void VoteCoinsEntry::updateDisplayUnit()
{
    if(model && model->getOptionsModel())
    {
        // Update payAmount with the current unit
        //ui->payAmount->setDisplayUnit(model->getOptionsModel()->getDisplayUnit());
    }
}

void VoteCoinsEntry::on_QuickPick_clicked()
{
    srand( time( NULL ) +rand());
    std::set<int> drawnNumbers;
    do{
        int proposedNumber=(rand()%42);
        if(drawnNumbers.find(proposedNumber)==drawnNumbers.end()){
            drawnNumbers.insert(proposedNumber);
        }
    }while(drawnNumbers.size()<6);

    std::set<int>::iterator it;
    it=drawnNumbers.begin();
    int num=*it;
    ui->number1->setCurrentIndex(num);
    it++;num=*it;
    ui->number1_2->setCurrentIndex(num);
    it++;num=*it;
    ui->number1_3->setCurrentIndex(num);
    it++;num=*it;
    ui->number1_4->setCurrentIndex(num);
    it++;num=*it;
    ui->number1_5->setCurrentIndex(num);
    it++;num=*it;
    ui->number1_6->setCurrentIndex(num);
}
