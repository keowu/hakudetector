#ifndef PROCESSANALYSER_H
#define PROCESSANALYSER_H

#include <QDialog>

namespace Ui {
class processanalyser;
}

class processanalyser : public QDialog
{
    Q_OBJECT

public:
    explicit processanalyser(QWidget *parent = nullptr);
    ~processanalyser();

private slots:
    void on_pushButton_clicked();

    void on_pushButton_2_clicked();

private:
    Ui::processanalyser *ui;
};

#endif // PROCESSANALYSER_H
