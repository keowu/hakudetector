#ifndef PROCESSVIEWER_H
#define PROCESSVIEWER_H

#include <QDialog>

namespace Ui {
class ProcessViewer;
}

class ProcessViewer : public QDialog
{
    Q_OBJECT

public:
    explicit ProcessViewer(QWidget *parent = nullptr);
    ~ProcessViewer();

private slots:

    void on_ProcessViewer_finished(int result);


    void on_pushButton_clicked();

private:
    Ui::ProcessViewer *ui;
};

#endif // PROCESSVIEWER_H
