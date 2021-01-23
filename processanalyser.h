#ifndef PROCESSANALYSER_H
#define PROCESSANALYSER_H

#include <QDialog>
#include <QDragEnterEvent>
#include <QMimeData>
#include <packerprotectordetect.h>
#include <fileSignature.h>

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

    void on_pushButton_3_clicked();

    void on_pushButton_4_clicked();

protected:
    void dropEvent(QDropEvent *event) override;
    void dragEnterEvent(QDragEnterEvent *event) override;

private:
    Ui::processanalyser *ui;
};

#endif // PROCESSANALYSER_H
