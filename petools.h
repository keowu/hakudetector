#ifndef PETOOLS_H
#define PETOOLS_H

#include <QDialog>

namespace Ui {
class petools;
}

class petools : public QDialog
{
    Q_OBJECT

public:
    explicit petools(QWidget *parent = nullptr);
    ~petools();
    void setMemoryFile(QByteArray memorymap);

private slots:


private:
    Ui::petools *ui;
};

#endif // PETOOLS_H
