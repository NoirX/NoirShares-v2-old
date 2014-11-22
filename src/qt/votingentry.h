// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
// Copyright (c) 2013-2014 Memorycoin Dev Team

#ifndef VOTECOINSENTRY_H
#define VOTECOINSENTRY_H

#include <QFrame>
#include "sendcoinsdialog.h"

namespace Ui {
    class VotingEntry;
}
class WalletModel;
//class VotingRecipient;

/** A single entry in the dialog for sending memorycoins. */
class VotingEntry : public QFrame
{
    Q_OBJECT

public:
    explicit VotingEntry(QWidget *parent = 0);
    ~VotingEntry();

    void setModel(WalletModel *model);
    bool validate();
    SendCoinsRecipient getValue();

    /** Return whether the entry is still empty and unedited */
    bool isClear();

    void setValue(const SendCoinsRecipient &value);
    void setAddress(const QString &address);

    /** Set up the tab chain manually, as Qt messes up the tab chain by default in some cases (issue https://bugreports.qt-project.org/browse/QTBUG-10907).
     */
    QWidget *setupTabChain(QWidget *prev);

    void setFocus();

public slots:
    void setRemoveEnabled(bool enabled);
    void clear();

signals:
    void removeEntry(VotingEntry *entry);

private slots:
    void on_deleteButton_clicked();
    void on_payTo_textChanged(const QString &address);
    void on_addressBookButton_clicked();
    void on_pasteButton_clicked();
    void updateDisplayUnit();

private:
    Ui::VotingEntry *ui;
    WalletModel *model;
};

#endif // VOTECOINSENTRY_H
