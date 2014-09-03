// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
// Copyright (c) 2013-2014 Memorycoin Dev Team

#ifndef VOTINGDIALOG_H
#define VOTINGDIALOG_H

#include <QDialog>
#include <sendcoinsdialog.h>

namespace Ui {
    class VotingDialog;
}
class WalletModel;
class VotingEntry;


QT_BEGIN_NAMESPACE
class QUrl;
QT_END_NAMESPACE

/** Dialog for sending NoirShares */
class VotingDialog : public QDialog
{
    Q_OBJECT

public:
    explicit VotingDialog(QWidget *parent = 0);
    ~VotingDialog();

    void setModel(WalletModel *model);

    /** Set up the tab chain manually, as Qt messes up the tab chain by default in some cases (issue https://bugreports.qt-project.org/browse/QTBUG-10907).
     */
    QWidget *setupTabChain(QWidget *prev);

    void setAddress(const QString &address);
    void pasteEntry(const SendCoinsRecipient &rv);
    bool handleURI(const QString &uri);

public slots:
    void clear();
    void reject();
    void accept();
    VotingEntry *addEntry();
    void updateRemoveEnabled();
    //void checkSweep();
    void sendToRecipients(bool sweep, qint64 sweepFee);

    //void setBalance(qint64 balance, qint64 unconfirmedBalance, qint64 immatureBalance);

private:
    Ui::VotingDialog *ui;
    WalletModel *model;
    bool fNewRecipientAllowed;

private slots:
    void on_sendButton_clicked();
    void on_sweepButton_clicked();
    void removeEntry(VotingEntry* entry);
    //void updateDisplayUnit();
};

#endif // VOTECOINSDIALOG_H
