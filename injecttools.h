#ifndef INJECTTOOLS_H
#define INJECTTOOLS_H

#include <QDialog>

namespace Ui {
class injecttools;
}

class injecttools : public QDialog
{
    Q_OBJECT

public:
    explicit injecttools(QWidget *parent = nullptr);
    void isUSERANDMIN(bool op);
    ~injecttools();

private slots:
    void on_pushButton_5_clicked();

    void on_pushButton_clicked();

    void on_pushButton_2_clicked();

private:
    Ui::injecttools *ui;
};

#endif // INJECTTOOLS_H
